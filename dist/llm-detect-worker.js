import {
  detectByLocalModel
} from "./chunk-UQH26TBD.js";

// src/llm-detect-worker.ts
import { runAsWorker } from "synckit";
runAsWorker(async (context, config) => {
  return await detectByLocalModel(context, config);
});
