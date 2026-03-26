import {
  detectByLocalModel
} from "./chunk-KZMPKJWE.js";

// src/llm-detect-worker.ts
import { runAsWorker } from "synckit";
runAsWorker(async (context, config) => {
  return await detectByLocalModel(context, config);
});
