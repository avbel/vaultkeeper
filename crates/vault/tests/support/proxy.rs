//! A TCP forwarder in front of the shared Vaultwarden, so one scenario can take "its" server
//! offline (and back) without disturbing the others running in parallel.

use std::sync::{Arc, Mutex};

use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    task::JoinSet,
};
use url::Url;

pub struct Proxy {
    port: u16,
    target: String,
    tasks: Arc<Mutex<Option<JoinSet<()>>>>,
}

impl Proxy {
    pub async fn start(server: &Url) -> Self {
        let target = format!(
            "{}:{}",
            server.host_str().unwrap(),
            server.port_or_known_default().unwrap()
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let proxy = Self {
            port,
            target,
            tasks: Arc::new(Mutex::new(None)),
        };
        proxy.serve(listener);
        proxy
    }

    pub fn url(&self) -> Url {
        Url::parse(&format!("http://127.0.0.1:{}", self.port)).unwrap()
    }

    /// Refuses new connections and cuts every open one, like a server that went away.
    pub fn stop(&self) {
        if let Some(mut tasks) = self.tasks.lock().unwrap().take() {
            tasks.abort_all();
        }
    }

    /// Listens on the same port again.
    pub async fn resume(&self) {
        let listener = TcpListener::bind(("127.0.0.1", self.port)).await.unwrap();
        self.serve(listener);
    }

    fn serve(&self, listener: TcpListener) {
        let target = self.target.clone();
        let connections = Arc::clone(&self.tasks);
        let mut guard = self.tasks.lock().unwrap();
        let tasks = guard.insert(JoinSet::new());
        tasks.spawn(async move {
            loop {
                let Ok((mut inbound, _)) = listener.accept().await else {
                    return;
                };
                let target = target.clone();
                let forward = async move {
                    if let Ok(mut outbound) = TcpStream::connect(&target).await {
                        let _ = copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                };
                if let Some(set) = connections.lock().unwrap().as_mut() {
                    set.spawn(forward);
                }
            }
        });
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop();
    }
}
