// Separate local workerd service for the controlled G4 IdP. The fused cohort
// reaches it through a Worker service binding, never through an Auth handler.
import { fixture } from "./idp-fixture.mjs";

export default {
  async fetch(request, env) {
    return (await fixture(request, env)) ?? new Response("Not found", { status: 404 });
  },
};
