const HtmlWebPackPlugin = require("html-webpack-plugin");
const MiniCssExtractPlugin = require("mini-css-extract-plugin");
const webpack = require('webpack')

const path = require('path');

module.exports = {
  entry: {
    main: ['webpack-hot-middleware/client?path=/__webpack_hmr&timeout=20000&noInfo=true&quiet=true', './src/index.js']
  },
  output: {
    path: path.join(__dirname, 'dist'),
    publicPath: '/explorer/',
    filename: '[name].js',
  },
  mode: 'development',
  stats: 'errors-only',
  node: {
    fs: "empty"
  },
  target: 'web',
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: "babel-loader",
        },
      },
      {
        test: /\.html$/,
        use: [
          {
            loader: "html-loader"
          },
        ]
      },
      {
        test: /\.(s*)css$/,
        use: [
          {
            loader: MiniCssExtractPlugin.loader,
          },
          "css-loader"
        ]
      },
      {
        test: /\.(png|svg|jpg|ico|gif)$/,
        use: [
          // {  loader: 'url-loader'},
          {
            loader: 'file-loader',
            options: {
              // limit: 4000000,
              name: 'images/[hash]-[name].[ext]'
            }
          }
        ]
      }
    ]
  },
  resolve: {
    alias: {
      Components: path.resolve(__dirname, 'src/assets/views/components'),
      Config: path.resolve(__dirname, 'config'),
      Pages: path.resolve(__dirname, 'src/assets/views/pages'),
      Actions: path.resolve(__dirname, 'src/assets/controller/actions'),
      Stylesheets: path.resolve(__dirname, 'src/assets/stylesheets'),
      Images: path.resolve(__dirname, 'src/assets/images')
    }
  },
  plugins: [
    new HtmlWebPackPlugin({
      template: "./src/index.html",
      filename: "./index.html"
    }),
    new MiniCssExtractPlugin({
      filename: "./bundle.css",
      chunkFilename: "[id].css"
    }),
    new webpack.HotModuleReplacementPlugin()
  ]
}