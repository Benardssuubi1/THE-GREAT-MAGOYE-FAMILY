import { getDb, cors } from './_db.js';

export default async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  const db = await getDb();
  const col = db.collection('chat');

  if (req.method === 'GET') {
    const items = await col.find({}).sort({ created_at: 1 }).limit(200).toArray();
    return res.json(items.map(i => ({ ...i, id: i._id })));
  }
  if (req.method === 'POST') {
    const doc = { ...req.body, created_at: new Date() };
    await col.insertOne(doc);
    return res.status(201).json({ ok: true });
  }
  res.status(405).end();
}
