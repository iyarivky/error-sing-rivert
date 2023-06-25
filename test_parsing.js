let urlString = "vmess://eyJhZGQiOiAic2cyLXJheS5pcHNlcnZlcnMueHl6IiwgImhvc3QiOiAic25pLmNsb3VkZmxhcmUuY29tIiwgImFpZCI6IDAsICJ0eXBlIjogIiIsICJwYXRoIjogIi9KQUdPQU5TU0gvIiwgIm5ldCI6ICJ3cyIsICJwcyI6ICJqYWdvYW5zc2gtZ29kZGFtbiIsICJ0bHMiOiAidGxzIiwgInR5cGUiOiAibm9uZSIsICJwb3J0IjogIjQ0MyIsICJ2IjogIjIiLCAiaWQiOiAiNGE0NWU0NzctY2ZhMS00YTBmLWEwYjAtZTQ1MTczYzYyZjViIn0=";
//let urlString = "vless://a771070c-b93e-4f72-8747-657f4a41ead9@sglws.mainssh.xyz:443?path=/vless&security=tls&encryption=none&host=sglws.mainssh.xyz&type=ws&sni=sglws.mainssh.xyz#mainssh-legendo"
const urlObj = new URL(urlString);

const protocol = urlObj.protocol;
const hostname = urlObj.hostname;
const pathname = urlObj.pathname;
const searchParams = urlObj.searchParams;
//parsedUrl.searchParams.get("type")

console.log(protocol); 
console.log(hostname);
console.log(urlObj.username);
console.log(urlObj.href);
console.log(searchParams.get("type"));
//console.log(searchParams.get("param2"));