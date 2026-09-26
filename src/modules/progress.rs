use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const STATUS_PENDING: u8 = 0;
pub const STATUS_RUNNING: u8 = 1;
pub const STATUS_DONE: u8 = 2;
pub const STATUS_FAILED: u8 = 3;

#[derive(Clone)]
pub struct TaskInfo {
    pub name: String,
    pub status: Arc<AtomicU8>,
    pub duration_ms: Arc<AtomicU64>,
    pub detail: Arc<Mutex<String>>,
}

pub struct ProgressTracker {
    target: String,
    tasks: Vec<TaskInfo>,
    is_active: Arc<AtomicBool>,
    enabled: bool,
    start_time: Instant,
    active_msg: Arc<Mutex<String>>,
}

#[allow(dead_code)]
impl ProgressTracker {
    pub fn new(target: &str, task_names: &[&str], enabled: bool) -> Arc<Self> {
        let tasks = task_names
            .iter()
            .map(|&name| TaskInfo {
                name: name.to_string(),
                status: Arc::new(AtomicU8::new(STATUS_PENDING)),
                duration_ms: Arc::new(AtomicU64::new(0)),
                detail: Arc::new(Mutex::new(String::new())),
            })
            .collect();

        Arc::new(Self {
            target: target.to_string(),
            tasks,
            is_active: Arc::new(AtomicBool::new(false)),
            enabled,
            start_time: Instant::now(),
            active_msg: Arc::new(Mutex::new("Démarrage de l'orchestrateur...".to_string())),
        })
    }

    pub fn set_running(&self, index: usize, detail: &str) {
        if index < self.tasks.len() {
            self.tasks[index].status.store(STATUS_RUNNING, Ordering::SeqCst);
            {
                let mut d = self.tasks[index].detail.lock().unwrap_or_else(|e| e.into_inner());
                *d = detail.to_string();
            }
            if let Ok(mut a) = self.active_msg.lock() {
                *a = format!("[{}] {}", self.tasks[index].name, detail);
            }
        }
    }

    pub fn set_done(&self, index: usize, duration: Duration) {
        if index < self.tasks.len() {
            self.tasks[index].status.store(STATUS_DONE, Ordering::SeqCst);
            self.tasks[index]
                .duration_ms
                .store(duration.as_millis() as u64, Ordering::SeqCst);
        }
    }

    pub fn set_failed(&self, index: usize, duration: Duration) {
        if index < self.tasks.len() {
            self.tasks[index].status.store(STATUS_FAILED, Ordering::SeqCst);
            self.tasks[index]
                .duration_ms
                .store(duration.as_millis() as u64, Ordering::SeqCst);
        }
    }

    pub fn set_detail(&self, index: usize, detail: &str) {
        if index < self.tasks.len() {
            {
                let mut d = self.tasks[index].detail.lock().unwrap_or_else(|e| e.into_inner());
                *d = detail.to_string();
            }
            if let Ok(mut a) = self.active_msg.lock() {
                *a = format!("[{}] {}", self.tasks[index].name, detail);
            }
        }
    }

    pub fn start(self: &Arc<Self>) -> Option<JoinHandle<()>> {
        if !self.enabled {
            return None;
        }

        self.is_active.store(true, Ordering::SeqCst);
        let tracker = Arc::clone(self);

        // Nettoie l'écran et cache le curseur pour un affichage TUI plein écran net
        print!("\x1b[2J\x1b[H\x1b[?25l");
        let _ = io::stdout().flush();

        let handle = thread::spawn(move || {
            let spinners = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
            let mut tick = 0usize;
            let mut is_first_render = true;

            let total_tasks = tracker.tasks.len();
            let num_rows = total_tasks.div_ceil(2);
            // 11 (logo) + 1 (vide) + 4 (hud) + 1 (vide) + 1 (progression) + 1 (vide) + 2 (grid borders) + num_rows + 1 (activité) = 22 + num_rows
            let total_lines = 22 + num_rows;
            let move_up = total_lines.saturating_sub(1);

            while tracker.is_active.load(Ordering::SeqCst) {
                if !is_first_render {
                    // Remonte le curseur pour réécrire tout le bloc TUI de façon fluide
                    print!("\x1b[{}A\r", move_up);
                } else {
                    is_first_render = false;
                }

                tracker.render_frame(spinners[tick % spinners.len()]);
                tick = tick.wrapping_add(1);

                thread::sleep(Duration::from_millis(80));
            }
        });

        Some(handle)
    }

    pub fn finish(&self, ticker_handle: Option<JoinHandle<()>>) {
        if !self.enabled {
            return;
        }

        self.is_active.store(false, Ordering::SeqCst);
        if let Some(handle) = ticker_handle {
            let _ = handle.join();
        }

        let total_tasks = self.tasks.len();
        let num_rows = total_tasks.div_ceil(2);
        let total_lines = 22 + num_rows;
        let move_up = total_lines.saturating_sub(1);

        // Réécriture finale avec validation
        print!("\x1b[{}A\r", move_up);
        self.render_frame('✓');

        // Restaure le curseur
        print!("\x1b[?25h\n\n");
        let _ = io::stdout().flush();
    }

    fn render_frame(&self, spinner: char) {
        let total = self.tasks.len();
        let mut completed = 0;
        let mut running_count = 0;

        for t in &self.tasks {
            match t.status.load(Ordering::SeqCst) {
                STATUS_DONE => completed += 1,
                STATUS_RUNNING => running_count += 1,
                _ => {}
            }
        }

        let percent = (completed * 100usize).checked_div(total).unwrap_or(100);
        let elapsed = self.start_time.elapsed().as_secs();
        let elapsed_str = format!("{:02}:{:02}s", elapsed / 60, elapsed % 60);

        // 1. Logo ASCII Veridy Boxé (Identique à l'image SVG)
        println!("\x1b[2K\r\x1b[38;5;141m╔══════════════════════════════════════════════════════════════════════════════╗\x1b[0m");
        println!("\x1b[2K\r\x1b[38;5;141m║                                                                              ║\x1b[0m");
        println!("\x1b[2K\r\x1b[38;5;141m║\x1b[38;5;51m\x1b[1m                ██╗   ██╗███████╗██████╗ ██╗██████╗ ██╗   ██╗                 \x1b[0m\x1b[38;5;141m║\x1b[0m");
        println!("\x1b[2K\r\x1b[38;5;141m║\x1b[38;5;51m\x1b[1m                ██║   ██║██╔════╝██╔══██╗██║██╔══██╗╚██╗ ██╔╝                 \x1b[0m\x1b[38;5;141m║\x1b[0m");
        println!("\x1b[2K\r\x1b[38;5;141m║\x1b[38;5;51m\x1b[1m                ██║   ██║█████╗  ██████╔╝██║██║  ██║ ╚████╔╝                  \x1b[0m\x1b[38;5;141m║\x1b[0m");
        println!("\x1b[2K\r\x1b[38;5;141m║\x1b[38;5;51m\x1b[1m                ╚██╗ ██╔╝██╔══╝  ██╔══██╗██║██║  ██║  ╚██╔╝                   \x1b[0m\x1b[38;5;141m║\x1b[0m");
        println!("\x1b[2K\r\x1b[38;5;141m║\x1b[38;5;51m\x1b[1m                 ╚████╔╝ ███████╗██║  ██║██║██████╔╝   ██║                    \x1b[0m\x1b[38;5;141m║\x1b[0m");
        println!("\x1b[2K\r\x1b[38;5;141m║\x1b[38;5;51m\x1b[1m                  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝╚═════╝    ╚═╝                    \x1b[0m\x1b[38;5;141m║\x1b[0m");
        println!("\x1b[2K\r\x1b[38;5;141m║                                                                              ║\x1b[0m");
        println!("\x1b[2K\r\x1b[38;5;141m║\x1b[38;5;39m\x1b[1m                CYBER INTELLIGENCE & OFFENSIVE SURFACE ENGINE                 \x1b[0m\x1b[38;5;141m║\x1b[0m");
        println!("\x1b[2K\r\x1b[38;5;141m╚══════════════════════════════════════════════════════════════════════════════╝\x1b[0m");
        println!("\x1b[2K\r");

        // 2. Header HUD Box
        println!("\x1b[2K\r\x1b[38;5;141m╔══════════════════════════════════════════════════════════════════════════════╗\x1b[0m");
        println!(
            "\x1b[2K\r\x1b[38;5;141m║\x1b[0m \x1b[1m\x1b[38;5;51m>> VERIDY OFFENSIVE ENGINE 360° — MONITOR D'AUDIT EN DIRECT <<\x1b[0m               \x1b[38;5;141m║\x1b[0m"
        );
        println!(
            "\x1b[2K\r\x1b[38;5;141m║\x1b[0m Cible : \x1b[38;5;220m\x1b[1m{:<18}\x1b[0m │ Durée : \x1b[38;5;51m{}\x1b[0m │ Moteurs actifs : \x1b[38;5;82m{}/{}\x1b[0m  \x1b[38;5;141m║\x1b[0m",
            self.target, elapsed_str, running_count, total
        );
        println!("\x1b[2K\r\x1b[38;5;141m╚══════════════════════════════════════════════════════════════════════════════╝\x1b[0m");
        println!("\x1b[2K\r");

        // 3. Barre de progression interactive
        let bar_width = 40;
        let filled = (percent * bar_width) / 100;
        let empty = bar_width - filled;
        let filled_str: String = "█".repeat(filled);
        let empty_str: String = "░".repeat(empty);

        println!(
            "\x1b[2K\r  Progression : [\x1b[38;5;51m{}\x1b[38;5;238m{}\x1b[0m] \x1b[1m\x1b[38;5;220m{:>3}%\x1b[0m  ({}/{} modules terminés)",
            filled_str, empty_str, percent, completed, total
        );
        println!("\x1b[2K\r");

        // 4. Grille à 2 colonnes
        let num_rows = total.div_ceil(2);
        println!("\x1b[2K\r\x1b[38;5;240m┌──────────────────────────────────────┬──────────────────────────────────────┐\x1b[0m");

        for r in 0..num_rows {
            let idx1 = r;
            let idx2 = r + num_rows;

            let col1 = self.render_task_cell(idx1, spinner);
            let col2 = if idx2 < total {
                self.render_task_cell(idx2, spinner)
            } else {
                "                                      ".to_string()
            };

            println!("\x1b[2K\r\x1b[38;5;240m│\x1b[0m {} \x1b[38;5;240m│\x1b[0m {} \x1b[38;5;240m│\x1b[0m", col1, col2);
        }

        println!("\x1b[2K\r\x1b[38;5;240m└──────────────────────────────────────┴──────────────────────────────────────┘\x1b[0m");

        // 5. Télémétrie en temps réel
        let act = self
            .active_msg
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|e| e.into_inner().clone());
        let truncated_act = if act.chars().count() > 68 {
            format!("{}...", act.chars().take(65).collect::<String>())
        } else {
            act
        };
        print!(
            "\x1b[2K\r  \x1b[38;5;198m⚡ Activité :\x1b[0m \x1b[38;5;255m{:<68}\x1b[0m",
            truncated_act
        );

        let _ = io::stdout().flush();
    }

    fn render_task_cell(&self, idx: usize, spinner: char) -> String {
        let task = &self.tasks[idx];
        let status = task.status.load(Ordering::SeqCst);
        let ms = task.duration_ms.load(Ordering::SeqCst);
        let name = &task.name;

        // Truncate name à 24 caractères (UTF-8 safe : on coupe aux frontières de chars)
        let disp_name = if name.chars().count() > 24 {
            name.chars().take(24).collect::<String>()
        } else {
            name.to_string()
        };

        match status {
            STATUS_DONE => {
                let dur_sec = ms as f64 / 1000.0;
                format!(
                    "\x1b[38;5;82m[✓]\x1b[0m \x1b[1m\x1b[38;5;255m{:<24}\x1b[0m \x1b[38;5;82m[{:4.1}s]\x1b[0m",
                    disp_name, dur_sec
                )
            }
            STATUS_RUNNING => {
                format!(
                    "\x1b[38;5;51m[{}]\x1b[0m \x1b[1m\x1b[38;5;255m{:<24}\x1b[0m \x1b[38;5;220m[EN COURS]\x1b[0m",
                    spinner, disp_name
                )
            }
            STATUS_FAILED => {
                format!(
                    "\x1b[38;5;196m[✗]\x1b[0m \x1b[38;5;245m{:<24}\x1b[0m \x1b[38;5;196m[ ÉCHEC ]\x1b[0m",
                    disp_name
                )
            }
            _ => {
                // PENDING
                format!(
                    "\x1b[38;5;240m[○]\x1b[0m \x1b[38;5;245m{:<24}\x1b[0m \x1b[38;5;240m[ATTENTE ]\x1b[0m",
                    disp_name
                )
            }
        }
    }
}
