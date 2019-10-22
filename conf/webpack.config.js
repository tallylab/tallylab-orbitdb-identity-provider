const path = require('path')

module.exports = {
  entry: './index.js',
  devtool: 'source-map',
  target: 'web',
  output: {
    libraryTarget: 'var',
    library: 'TallyLabIAM',
    filename: 'tallylab-orbitdb-iam.min.js',
    path: path.resolve('dist')
  }
}
