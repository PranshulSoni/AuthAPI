# AuthAPI

## Express setup note

Mount `express.json()` before the AuthAPI router so JSON request bodies are parsed:

```ts
app.use(express.json())
app.use("/auth", auth.router)
```

Express's default error handler may return an HTML stack trace when a client sends malformed JSON. In production apps, add your own error handler after your routes:

```ts
import { ErrorRequestHandler } from "express"

const jsonErrorHandler: ErrorRequestHandler = (err, _req, res, next) => {
  if (err instanceof SyntaxError && "body" in err) {
    res.status(400).json({ error: "Invalid JSON body" })
    return
  }

  next(err)
}

app.use(jsonErrorHandler)
```

This keeps invalid JSON responses clean and prevents internal file paths or stack traces from being exposed.
