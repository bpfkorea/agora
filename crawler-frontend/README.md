# Crawler frontend

Crawler frontend is the web frontend for processing the data gathered by the [Agora](https://github.com/bosagora/agora) project's network crawler.
It needs to be paired to an Agora network crawler by changing the build_config.json
located in the root directory of this repository.

# Build instructions

This frontend is based on Node.JS, and use Webpack to package the assets. Before
building the application the build_config.json needs to be modified.

## Building on Ubuntu

```sh
$ sudo apt-get install nodejs
$ sudo apt-get install npm
$ npm ci
$ npm run build-dev  // for development build
$ npm run build-prod // for production build
```

## Building on MacOS

```sh
$ /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
$ brew install node
$ npm ci
$ npm run build-dev  // for development build
$ npm run build-prod // for production build
```

# Usage

## Development

- use the following build_config.json

```json
{
    "google_maps_api_key": "<Please insert your google maps key here>",
    "agora_node_endpoint": "../../../test/data/network_info.json"
}
```
- rebuild the application in debug mode with
```sh
npm run build-dev
```

- start up the test http-server

```sh
http-server
```
