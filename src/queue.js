export class TaskQueue {
  constructor(concurrency = 1) {
    this.concurrency = Math.max(1, Number(concurrency) || 1);
    this.running = 0;
    this.queue = [];
    this.seq = 0;
  }
  push(fn) {
    const id = ++this.seq;
    return new Promise((resolve, reject) => {
      this.queue.push({ id, fn, resolve, reject });
      this.run();
    });
  }
  run() {
    while (this.running < this.concurrency && this.queue.length) {
      const task = this.queue.shift();
      this.running++;
      Promise.resolve()
        .then(task.fn)
        .then(v => {
          this.running--;
          task.resolve(v);
          this.run();
        })
        .catch(e => {
          this.running--;
          task.reject(e);
          this.run();
        });
    }
  }
}
