const path = require('path');

module.exports = {
    plugins: [
        [
            '@docusaurus/plugin-content-docs',
            {
                id: 'inx-faucet-develop',
                path: path.resolve(__dirname, 'docs'),
                routeBasePath: 'inx-faucet',
                sidebarPath: path.resolve(__dirname, 'sidebars.js'),
                editUrl: 'https://github.com/iotaledger/inx-faucet/edit/develop/documentation',
                versions: {
                    current: {
                        label: 'Develop',
                        path: 'develop',
                        badge: true
                    },
                },
            }
        ],
    ],
    staticDirectories: [path.resolve(__dirname, 'static')],
};
