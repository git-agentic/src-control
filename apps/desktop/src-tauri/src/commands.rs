use std::sync::Mutex;

use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

use crate::read_model::{
    DesktopRepository, FileChangeView, FileView, HistoryView, ReadModelError, RepositoryOverview,
    SnapshotDetails,
};

#[derive(Default)]
struct AppState {
    repository: Mutex<Option<DesktopRepository>>,
}

fn state_error() -> ReadModelError {
    ReadModelError {
        kind: "repository_error".into(),
        message: "Desktop repository state is unavailable.".into(),
    }
}

fn no_repository() -> ReadModelError {
    ReadModelError {
        kind: "no_repository".into(),
        message: "Choose a src-control repository first.".into(),
    }
}

fn selected_repository(state: &State<'_, AppState>) -> Result<DesktopRepository, ReadModelError> {
    let guard = state.repository.lock().map_err(|_| state_error())?;
    guard.as_ref().cloned().ok_or_else(no_repository)
}

fn task_error(error: impl std::fmt::Display) -> ReadModelError {
    ReadModelError {
        kind: "repository_error".into(),
        message: format!("Desktop repository query failed: {error}"),
    }
}

#[tauri::command]
async fn choose_repository(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<RepositoryOverview>, ReadModelError> {
    let (sender, mut receiver) = tauri::async_runtime::channel(1);
    app.dialog()
        .file()
        .set_title("Open src-control repository")
        .pick_folder(move |selected| {
            let _ = sender.try_send(selected);
        });
    let selected = receiver.recv().await.flatten();
    let Some(selected) = selected else {
        return Ok(None);
    };
    let path = selected.into_path().map_err(|error| ReadModelError {
        kind: "invalid_selection".into(),
        message: error.to_string(),
    })?;
    let (repository, overview) = tauri::async_runtime::spawn_blocking(move || {
        let repository = DesktopRepository::open(path)?;
        let overview = repository.overview()?;
        Ok::<_, ReadModelError>((repository, overview))
    })
    .await
    .map_err(task_error)??;
    *state.repository.lock().map_err(|_| state_error())? = Some(repository);
    Ok(Some(overview))
}

#[tauri::command]
async fn select_reference(
    state: State<'_, AppState>,
    reference_id: String,
) -> Result<HistoryView, ReadModelError> {
    let repository = selected_repository(&state)?;
    tauri::async_runtime::spawn_blocking(move || repository.select_reference(&reference_id))
        .await
        .map_err(task_error)?
}

#[tauri::command]
async fn snapshot_details(
    state: State<'_, AppState>,
    snapshot_id: String,
) -> Result<SnapshotDetails, ReadModelError> {
    let repository = selected_repository(&state)?;
    tauri::async_runtime::spawn_blocking(move || repository.snapshot_details(&snapshot_id))
        .await
        .map_err(task_error)?
}

#[tauri::command]
async fn read_file(
    state: State<'_, AppState>,
    snapshot_id: String,
    path: String,
) -> Result<FileView, ReadModelError> {
    let repository = selected_repository(&state)?;
    tauri::async_runtime::spawn_blocking(move || repository.read_file(&snapshot_id, &path))
        .await
        .map_err(task_error)?
}

#[tauri::command]
async fn compare_first_parent(
    state: State<'_, AppState>,
    snapshot_id: String,
    path: String,
) -> Result<FileChangeView, ReadModelError> {
    let repository = selected_repository(&state)?;
    tauri::async_runtime::spawn_blocking(move || {
        repository.compare_first_parent(&snapshot_id, &path)
    })
    .await
    .map_err(task_error)?
}

/// Build and run the Tauri shell with the narrow Phase 35 command set.
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            choose_repository,
            select_reference,
            snapshot_details,
            read_file,
            compare_first_parent
        ])
        .run(tauri::generate_context!())
        .expect("failed to run src-control desktop");
}
