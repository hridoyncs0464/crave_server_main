import bcrypt from 'bcrypt';

async function run() {
  const passwords = [
    { name: 'admin', pass: 'admin123' },
    { name: 'ahasana', pass: 'ahasana85' },
    { name: 'shifa', pass: 'shifa90' },
    { name: 'hridoy', pass: 'hridoy64' }
  ];
  for (const p of passwords) {
    const hash = await bcrypt.hash(p.pass, 10);
    console.log(p.name + ': ' + hash);
  }
}
run();