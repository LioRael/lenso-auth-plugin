using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [(name = "oauth-postgres", worker = .oauthPostgres)]
);

const oauthPostgres :Workerd.Worker = (
  modules = [
    (name = "worker.mjs", esModule = embed ".oauth-postgres/worker.mjs"),
    (name = "pkg/lenso_workers_g4_host_bg.wasm", wasm = embed ".oauth-postgres/lenso_workers_g4_host_bg.wasm")
  ],
  compatibilityDate = "2026-07-01",
  compatibilityFlags = ["nodejs_compat"]
);
