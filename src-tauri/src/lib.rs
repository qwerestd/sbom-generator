use std::fs;
use std::path::Path;
use tauri::command;

use sbom_generator::analyze::sbom_generate::analyze;
use sbom_generator::model::configuration::Configuration;

/// 原生文件对话框：选择待分析的项目文件夹
#[command]
fn pick_directory() -> Result<Option<String>, String> {
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-STA",
            "-Command",
            r#"Add-Type -AssemblyName System.Windows.Forms; $f = New-Object System.Windows.Forms.FolderBrowserDialog; $f.AutoUpgradeEnabled = $true; $f.Description = '请选择待分析的项目代码根目录'; if ($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { [Console]::Write($f.SelectedPath) }"#,
        ])
        .output()
        .map_err(|e| format!("启动文件夹选择器失败: {}", e))?;

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        Ok(None)
    } else {
        Ok(Some(path))
    }
}

/// 原生保存对话框：选择 SBOM 输出文件路径
#[command]
fn pick_save_file(default_name: Option<String>) -> Result<Option<String>, String> {
    let fname = default_name.unwrap_or_else(|| "sbom_result.json".to_string());
    let script = format!(
        r#"Add-Type -AssemblyName System.Windows.Forms; $s = New-Object System.Windows.Forms.SaveFileDialog; $s.Title = '选择 CycloneDX SBOM 保存位置'; $s.Filter = 'CycloneDX JSON (*.json)|*.json|All Files (*.*)|*.*'; $s.FileName = '{}'; if ($s.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {{ [Console]::Write($s.FileName) }}"#,
        fname
    );

    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-STA", "-Command", &script])
        .output()
        .map_err(|e| format!("启动文件保存对话框失败: {}", e))?;

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        Ok(None)
    } else {
        Ok(Some(path))
    }
}

/// 在 Windows 资源管理器中高亮定位生成的文件或打开目录
#[command]
fn open_in_explorer(path: String) -> Result<(), String> {
    let p = Path::new(&path);
    if p.exists() {
        if p.is_file() {
            let _ = std::process::Command::new("explorer")
                .arg(format!("/select,{}", path))
                .spawn();
        } else {
            let _ = std::process::Command::new("explorer").arg(&path).spawn();
        }
        Ok(())
    } else if let Some(parent) = p.parent() {
        if parent.exists() {
            let _ = std::process::Command::new("explorer").arg(parent).spawn();
            return Ok(());
        }
        Err("指定的路径不存在".to_string())
    } else {
        Err("指定的路径不存在".to_string())
    }
}

/// 核心 SBOM 依赖与漏洞态势分析
#[command]
async fn run_sbom_analyze(
    directory: String,
    output_path: String,
    dynamic: Option<bool>,
) -> Result<String, String> {
    let is_dynamic = dynamic.unwrap_or(true);
    let configuration = Configuration {
        directory: directory.clone(),
        output: output_path.clone(),
        use_debug: false,
        dynamic: is_dynamic,
    };

    let output_clone = output_path.clone();
    // 在专有系统 OS 线程中运行，彻底解耦 Tokio 异步运行时，绝不阻塞 UI 事件循环
    let handle = std::thread::Builder::new()
        .name("sbom-analyze-worker".into())
        .spawn(move || -> Result<String, String> {
            analyze(&configuration, is_dynamic).map_err(|e| e.to_string())?;
            fs::read_to_string(&output_clone)
                .map_err(|e| format!("读取已生成的 SBOM 文件失败: {}", e))
        })
        .map_err(|e| format!("启动分析工作线程失败: {}", e))?;

    handle
        .join()
        .map_err(|_| "分析工作线程发生异常中断".to_string())?
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            run_sbom_analyze,
            pick_directory,
            pick_save_file,
            open_in_explorer
        ])
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
