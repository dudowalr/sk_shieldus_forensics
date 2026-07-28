const nextVersion = require('next/package.json').version;
const reactVersion = require('react/package.json').version;
const reactDomVersion = require('react-dom/package.json').version;

/** @type {import('next').NextConfig} */
const nextConfig = {
  poweredByHeader: false,

  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'X-Powered-By',
            value: `Next.js/${nextVersion} React/${reactVersion}`,
          },
          {
            key: 'X-React-Version',
            value: reactVersion,
          },
          {
            key: 'X-React-DOM-Version',
            value: reactDomVersion,
          },
        ],
      },
    ];
  },
};

module.exports = nextConfig;