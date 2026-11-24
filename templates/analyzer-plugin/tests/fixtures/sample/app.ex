@route("GET", "/users/:id")
fn show(id) { db.find(id) }

@route("POST", "/users")
fn create(body) { db.insert(body) }
