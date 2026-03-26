import {
  detectByLocalModel
} from "./chunk-CD2H4EGT.js";

// src/llm-detect-worker.ts
import { runAsWorker } from "synckit";
runAsWorker(async (context, config) => {
  return await detectByLocalModel(context, config);
});
