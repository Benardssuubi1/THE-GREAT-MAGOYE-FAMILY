import { getDb, cors } from './_db.js';
import { ObjectId } from 'mongodb';

export default async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  const db = await getDb();
  const col = db.collection('updates');

  if (req.method === 'GET') {
    const items = await col.find({}).sort({ date: -1 }).toArray();
    return res.json(items.map(i => ({ ...i, id: i._id })));
  }
  if (req.method === 'POST') {
    const doc = { ...req.body, created_at: new Date() };
    const r = await col.insertOne(doc);
    return res.status(201).json({ ...doc, id: r.insertedId });
  }
  if (req.method === 'PATCH') {
    const { id, ...update } = req.body;
    await col.updateOne({ _id: new ObjectId(id) }, { $set: update });
    return res.json({ ok: true });
  }
  if (req.method === 'DELETE') {
    const { id } = req.query;
    await col.deleteOne({ _id: new ObjectId(id) });
    return res.json({ ok: true });
  }
  res.status(405).end();
}
