## Cacophoney
A chat application that has all the features of Discord, but decentralized and more private. This repository is for a cacophoney node, which communicates with clients.

## Features
These are the features that will be added or currently existing:

- [ ] Base application
- [ ] Terminal GUI \(Sort of done)
- [ ] HTTP/WebSockets proxy to allow browsers to connect
- [ ] WebRTC support for voice calling
- [ ] File upload support
- [ ] Client side application

    - [ ] Tauri/Svelte GUI
    - [ ] Basic Messaging functionality
    - [ ] Group chat support
    - [ ] "Server" or "Guild" support \(similar to existing Discord servers)

## How it works (communication protocl)
```mermaid
sequenceDiagram
  participant Bob
  participant Node
  participant Alice

  Bob->>Node: {identify: {public_key: 0x8327bbba, sig: 0x8292}}
  Node->>Bob: {accepted: true}
  Bob->>Node: {communication_request:{public_key:0x7872872}}
  Bob-->>+Node: Hello!
  Node-->>+Alice: Hello!
  Note left of Bob: Bob identifies themself with their public key to the node.
  Note left of Bob: Node accepts as the signature is valid.
  Note left of Bob: Bob requests to communicate with Alice's public key.
  Note over Alice,Bob: Bob can now communicate with Alice, with the node as a middleman.
```

## License
This work is licensed under the [Apache 2.0](/LICENSE) or [MIT](/LICENSE-MIT) license at your option.
