// Loads the wasm app; #[wasm_bindgen(start)] mounts it.
import init from "./pkg/web.js";

init().catch((err) => {
  console.error(err);
  document.body.textContent = "Failed to load the panel. Check the console.";
});
