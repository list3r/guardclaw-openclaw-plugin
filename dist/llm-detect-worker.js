import {
  detectByLocalModel
} from "./chunk-RLCI4KU5.js";

// src/llm-detect-worker.ts
import { runAsWorker } from "synckit";
runAsWorker(async (context, config) => {
  return await detectByLocalModel(context, config);
});
