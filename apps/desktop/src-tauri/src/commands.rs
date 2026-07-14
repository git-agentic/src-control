use std::sync::Mutex;

use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

use crate::read_model::{
    ComparisonView, DesktopRepository, FileView, HistoryView, ReadModelError, RepositoryOverview,
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

fn with_repository<T>(
    state: &State<'_, AppState>,
    read: impl FnOnce(&DesktopRepository) -> Result<T, ReadModelError>,
) -> Result<T, ReadModelError> {
    let guard = state.repository.lock().map_err(|_| state_error())?;
    read(guard.as_ref().ok_or_else(no_repository)?)
}

#[tauri::command]
async fn choose_repository(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<RepositoryOverview>, ReadModelError> {
    let selected = app
        .dialog()
        .file()
        .set_title("Open src-control repository")
        .blocking_pick_folder();
    let Some(selected) = selected else {
        return Ok(None);
    };
    let path = selected.into_path().map_err(|error| ReadModelError {
        kind: "invalid_selection".into(),
        message: error.to_string(),
    })?;
    let repository = DesktopRepository::open(path)?;
    let overview = repository.overview()?;
    *state.repository.lock().map_err(|_| state_error())? = Some(repository);
    Ok(Some(overview))
}

#[tauri::command]
fn select_reference(
    state: State<'_, AppState>,
    reference_id: String,
) -> Result<HistoryView, ReadModelError> {
    with_repository(&state, |repo| repo.select_reference(&reference_id))
}

#[tauri::command]
fn snapshot_details(
    state: State<'_, AppState>,
    snapshot_id: String,
) -> Result<SnapshotDetails, ReadModelError> {
    with_repository(&state, |repo| repo.snapshot_details(&snapshot_id))
}

#[tauri::command]
fn read_file(
    state: State<'_, AppState>,
    snapshot_id: String,
    path: String,
) -> Result<FileView, ReadModelError> {
    with_repository(&state, |repo| repo.read_file(&snapshot_id, &path))
}

#[tauri::command]
fn compare_first_parent(
    state: State<'_, AppState>,
    snapshot_id: String,
) -> Result<ComparisonView, ReadModelError> {
    with_repository(&state, |repo| repo.compare_first_parent(&snapshot_id))
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
