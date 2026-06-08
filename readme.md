# Guinea Pig

## Description
This repo contains a variety of code samples of vulnerabilities.


## VSCode configuration
You may be authenticated to github copilot to make it work.

Extension \ Select MCP Servers-installed \ Start Server.

NB: server configuration is in .vscode\mcp.json

## Claude code configuration 
```
claude mcp add --transport http --scope project my-serveur http://127.0.0.1:8000/mcp/
```


## Some prompts
### For all features secrets, sca and sast
```
Please scan my project for security vulnerabilities about secrets, sca and sast. Provide me a prioritization of identified vulnerabilities. And propose a modification of the code.

```

### For only secrets
```
Could you provide me with a list of all the secrets in this repo?
```

## Sources
I used mostly this one and modify some sca and sast files
https://github.com/dehvCurtis/vulnerable-code-examples

and some secrets from here
https://github.com/Yelp/detect-secrets/tree/master/test_data

