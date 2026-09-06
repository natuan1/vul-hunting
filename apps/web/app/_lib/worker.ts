// URL worker API nội bộ — dùng chung cho các proxy route
export const WORKER_URL = () => process.env.WORKER_API_URL ?? "http://worker:8000";
