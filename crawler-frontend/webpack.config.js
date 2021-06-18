const HtmlWebpackPlugin = require('html-webpack-plugin');
const CopyWebpackPlugin = require("copy-webpack-plugin");
const TerserPlugin = require("terser-webpack-plugin");
const path = require('path');

const build_config = require('./build_config.json')
console.log("building with config:\n")
console.log(build_config)

module.exports = {
    entry: {
        app: [
            './assets/index.js',
        ],
    },
    output: {
        filename: 'main.js',
        path: path.resolve(__dirname, 'dist'),
    },
    optimization: {
        minimizer: [
            new TerserPlugin({
                terserOptions: {
                    keep_fnames: true,
                },
            }),
        ],
    },
    plugins: [
        new HtmlWebpackPlugin({
            template: 'index_tmpl.html',
            google_maps_api_key: build_config.google_maps_api_key,
            agora_node_endpoint: build_config.agora_node_endpoint
        }),
        new CopyWebpackPlugin({
            patterns: [
                {
                    from: "./assets/bosagora/img/bosagora_favicon.png",
                    to: "./bosagora_favicon.png"
                }
            ]
        })
    ],
    module: {
        rules: [
            {
                test: /\.css$/i,
                use: ['style-loader', 'css-loader'],
            },
            {
                test: /\.(png|svg|jpg|jpeg|gif)$/i,
                type: 'asset/resource',
            },
            {
                test: /\.(woff|woff2|eot|ttf|otf)$/i,
                type: 'asset/resource',
            },
            {
                test: /\.yml$/i,
                type: 'json', // Required by Webpack v4
                use: 'yaml-loader'
            }
        ],
    },
};
