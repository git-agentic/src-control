//! S3-compatible `Bucket` backend (AWS, MinIO, R2 via AWS_ENDPOINT_URL_S3).

use crate::{validate_key, Bucket, Error, Fetched, Result};

/// A `Bucket` backed by an S3-compatible object store. Credentials, region,
/// and endpoint come entirely from the SDK's standard chain (`AWS_*` env,
/// shared config/credentials files, `AWS_ENDPOINT_URL_S3` for MinIO/R2/etc.)
/// — this crate adds no credential surface of its own. Runs its own
/// current-thread tokio runtime internally so the trait stays synchronous.
pub struct S3Bucket {
    rt: tokio::runtime::Runtime,
    client: aws_sdk_s3::Client,
    bucket: String,
    prefix: String,
}

impl S3Bucket {
    /// Connect to `bucket`, scoping every key under `prefix`, using the
    /// SDK's standard credential/region/endpoint resolution chain.
    pub fn open(bucket: &str, prefix: &str) -> Result<S3Bucket> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::Backend(format!("tokio runtime: {e}")))?;
        let conf = rt.block_on(aws_config::load_defaults(aws_config::BehaviorVersion::latest()));
        Ok(S3Bucket {
            client: aws_sdk_s3::Client::new(&conf),
            rt,
            bucket: bucket.to_string(),
            prefix: prefix.trim_matches('/').to_string(),
        })
    }

    /// Validate `key` and join it onto this bucket's prefix.
    fn full_key(&self, key: &str) -> Result<String> {
        validate_key(key)?;
        Ok(if self.prefix.is_empty() { key.to_string() } else { format!("{}/{key}", self.prefix) })
    }
}

/// HTTP status of a failed S3 SDK call, if the error carries a raw response.
fn http_status<E>(err: &aws_sdk_s3::error::SdkError<E>) -> Option<u16> {
    err.raw_response().map(|r| r.status().as_u16())
}

impl Bucket for S3Bucket {
    fn get(&self, key: &str, cached_tag: Option<&str>) -> Result<Fetched> {
        let k = self.full_key(key)?;
        let mut req = self.client.get_object().bucket(&self.bucket).key(&k);
        if let Some(tag) = cached_tag {
            req = req.if_none_match(tag);
        }
        let send_result = self.rt.block_on(req.send());
        match send_result {
            Ok(out) => {
                let tag = out.e_tag().unwrap_or_default().to_string();
                let bytes = self
                    .rt
                    .block_on(out.body.collect())
                    .map_err(|e| Error::Backend(format!("s3 get body {k}: {e}")))?
                    .into_bytes()
                    .to_vec();
                Ok(Fetched::New { bytes, tag })
            }
            Err(e) => {
                // 304 => Unchanged (if_none_match precondition); NoSuchKey/404 => Absent.
                let status = http_status(&e);
                let code = e
                    .as_service_error()
                    .and_then(aws_sdk_s3::error::ProvideErrorMetadata::code)
                    .unwrap_or_default();
                match (code, status) {
                    (_, Some(304)) => Ok(Fetched::Unchanged),
                    // Checked before the bare-404 fallback below because a
                    // missing bucket surfaces as 404 too. When the backend
                    // supplies the body error code, a missing bucket is a
                    // hard config error, not an absent object — without this
                    // arm it would fall through to `Fetched::Absent` and make
                    // a typo'd/nonexistent bucket look like a real, empty
                    // remote (`sc fetch` "succeeds" against nothing). Some
                    // S3-compatibles omit the code on a 404 entirely; those
                    // still classify as `Absent` here (bare-404 fallback,
                    // unchanged) — distinguishing that case needs a
                    // `HeadBucket` probe, not attempted here.
                    ("NoSuchBucket", _) => Err(Error::Backend(format!(
                        "s3 bucket {} does not exist (check the sc+s3:// url)",
                        self.bucket
                    ))),
                    ("NoSuchKey", _) | (_, Some(404)) => Ok(Fetched::Absent),
                    _ => Err(Error::Backend(format!("s3 get {k}: {e}"))),
                }
            }
        }
    }

    fn put_new(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        let k = self.full_key(key)?;
        let req = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&k)
            .if_none_match("*")
            .body(bytes.to_vec().into());
        match self.rt.block_on(req.send()) {
            Ok(_) => Ok(true),
            Err(e) if http_status(&e) == Some(412) => Ok(false),
            Err(e) => Err(Error::Backend(format!("s3 put_new {k}: {e}"))),
        }
    }

    fn put_if_tag(&self, key: &str, bytes: &[u8], expected_tag: Option<&str>) -> Result<Option<String>> {
        let k = self.full_key(key)?;
        let mut req = self.client.put_object().bucket(&self.bucket).key(&k).body(bytes.to_vec().into());
        req = match expected_tag {
            Some(tag) => req.if_match(tag),
            None => req.if_none_match("*"),
        };
        match self.rt.block_on(req.send()) {
            Ok(out) => Ok(Some(out.e_tag().unwrap_or_default().to_string())),
            Err(e) if http_status(&e) == Some(412) => Ok(None),
            Err(e) => Err(Error::Backend(format!("s3 put_if_tag {k}: {e}"))),
        }
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let full = self.full_key(prefix.trim_end_matches('/'))?;
        let mut out = Vec::new();
        let mut cont: Option<String> = None;
        loop {
            let mut req = self.client.list_objects_v2().bucket(&self.bucket).prefix(format!("{full}/"));
            if let Some(c) = &cont {
                req = req.continuation_token(c);
            }
            let resp = self.rt.block_on(req.send()).map_err(|e| Error::Backend(format!("s3 list: {e}")))?;
            for obj in resp.contents() {
                if let Some(k) = obj.key() {
                    let rel = k.strip_prefix(&self.prefix).unwrap_or(k).trim_start_matches('/');
                    out.push(rel.to_string());
                }
            }
            match resp.next_continuation_token() {
                Some(c) => cont = Some(c.to_string()),
                None => break,
            }
        }
        out.sort();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    /// Live-backend parity: set SC_OBJIO_S3_BUCKET (and standard AWS_* env,
    /// e.g. AWS_ENDPOINT_URL_S3 for MinIO) to run; skipped otherwise so CI
    /// stays hermetic on DirBucket.
    #[test]
    fn s3_bucket_passes_contract_when_configured() {
        let Ok(bucket) = std::env::var("SC_OBJIO_S3_BUCKET") else {
            eprintln!("skipped: SC_OBJIO_S3_BUCKET not set");
            return;
        };
        let prefix = format!("scl-objio-contract-{}", std::process::id());
        let b = super::S3Bucket::open(&bucket, &prefix).unwrap();
        crate::contract_suite(&b);
    }
}
