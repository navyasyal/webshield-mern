import { Queue } from 'bullmq';
const connection={url:process.env.REDIS_URL||'redis://localhost:6379',maxRetriesPerRequest:null};
export const scanQueue=new Queue('scans',{connection});
