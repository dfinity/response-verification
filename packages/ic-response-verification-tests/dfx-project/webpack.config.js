const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const CopyPlugin = require('copy-webpack-plugin');

const frontendDirectory = 'frontend';

const frontend_entry = path.join(__dirname, 'canisters', 'frontend', 'src');

module.exports = {
  target: 'web',
  mode: 'development',
  entry: {
    index: path.join(frontend_entry, 'index.js'),
  },
  resolve: {
    extensions: ['.js', '.ts', '.jsx', '.tsx'],
  },
  output: {
    filename: 'index.js',
    path: path.join(__dirname, 'dist', 'frontend'),
  },

  plugins: [
    new HtmlWebpackPlugin({
      template: path.join(frontend_entry, 'index.html'),
      cache: false,
    }),
    new CopyPlugin({
      patterns: [
        {
          from: 'canisters/frontend/.ic-assets.json*',
          to: '.ic-assets.json5',
          noErrorOnMissing: true,
        },
      ],
    }),
  ],
};
