const path = require('path')

module.exports = {
  entry: './index.js',
  devtool: 'source-map',
  target: 'web',
  output: {
    libraryTarget: 'var',
    library: 'TallyLabIdentities',
    filename: 'tallylab-orbitdb-identities.min.js',
    path: path.resolve('dist')
  }
}
