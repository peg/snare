import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";

// Run production SQL, including constraints and rollback, against SQLite.
// This adapter deliberately implements no ownership, quota, or lease policy.
class SQLiteD1 {
  constructor() {
    this.sqlite = new DatabaseSync(":memory:");
    this.sqlite.exec(readFileSync(new URL("../migrations/0001_state.sql", import.meta.url), "utf8"));
    this.queryCount = 0;
  }

  prepare(sql) {
    const db = this.sqlite;
    const adapter = this;
    let values = [];
    const query = {
      bind(...bound) { values = bound; return query; },
      execute() {
        adapter.queryCount++;
        const statement = db.prepare(sql);
        const before = Number(db.prepare("SELECT total_changes() AS n").get().n);
        let results = [];
        if (statement.columns().length) results = statement.all(...values).map(row => ({ ...row }));
        else statement.run(...values);
        const changes = Number(db.prepare("SELECT total_changes() AS n").get().n) - before;
        return { success: true, meta: { changes }, results };
      },
      async run() { return query.execute(); },
      async all() { return query.execute(); },
      async first() { return query.execute().results[0] ?? null; },
    };
    return query;
  }

  async batch(statements) {
    this.sqlite.exec("BEGIN IMMEDIATE");
    try {
      const result = statements.map(statement => statement.execute());
      this.sqlite.exec("COMMIT");
      return result;
    } catch (error) {
      this.sqlite.exec("ROLLBACK");
      throw error;
    }
  }

  count(table) {
    if (!/^[a-z_]+$/.test(table)) throw new Error("invalid fixture table");
    return Number(this.sqlite.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n);
  }

  changes() { return Number(this.sqlite.prepare("SELECT total_changes() AS n").get().n); }
  resetQueryCount() { this.queryCount = 0; }
  close() { this.sqlite.close(); }
}

export { SQLiteD1 };
