from Crypto import app
from Crypto import routes
import uvicorn

uvicorn.run(app, host="127.0.0.1", port=5000, log_level="info")
