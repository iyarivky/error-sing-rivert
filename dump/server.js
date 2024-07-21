import http from "http";
import fs from "fs";

const server = http.createServer((req, res) => {
  fs.readFile('script.js', (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end(JSON.stringify(err));
      return;
    }
    res.writeHead(200);
    res.end(data);
  });
});

server.listen(8080);