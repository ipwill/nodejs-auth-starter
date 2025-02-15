const path = require('path');

module.exports = {
  mode: 'development',
  entry: ['./src/app.js', './public/js/script.js'],
  output: {
    path: path.resolve(__dirname, 'public/js'),
    filename: 'bundle.js',
    publicPath: '/js/'
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['@babel/preset-env'],
          },
        },
      },
    ],
  },
  devtool: 'source-map',
  devServer: {
  static: {
    directory: path.join(__dirname, 'public'),
  },
  compress: true,
  port: 3000,
  hot: true,
  liveReload: true,
  historyApiFallback: true,
  }
};
