use tauri::command;
// 引入你外层库所需的分析函数和配置结构体
use sbom_generator::analyze::sbom_generate::analyze;
use sbom_generator::model::configuration::Configuration;
use std::fs;
// 1. 在参数里增加 output_path
#[command]
async fn run_sbom_analyze(directory: String, output_path: String) -> Result<String, String> {

    // 2. 使用前端传过来的路径
    let configuration = Configuration {
        directory: directory.clone(),
        output: output_path.clone(), // 动态设定保存位置
        use_debug: false,
        dynamic: true,
    };

    // 调用核心逻辑生成文件
    match analyze(&configuration, true) {
        Ok(_) => {
            // 生成成功后，直接读取用户指定位置的 JSON 文件内容返回给前端展示
            match fs::read_to_string(&output_path) {
                Ok(json_content) => Ok(json_content),
                Err(e) => Err(format!("文件已成功保存到 {}，但前端读取渲染失败: {}", output_path, e))
            }
        },
        Err(e) => Err(format!("分析失败: {}", e)),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![run_sbom_analyze])
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