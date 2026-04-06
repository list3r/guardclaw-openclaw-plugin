import {
  detectByLocalModel
} from "./chunk-FMLGWCSX.js";

// src/llm-detect-worker.ts
import { runAsWorker } from "synckit";
runAsWorker(async (context, config) => {
  return await detectByLocalModel(context, config);
});
