<p align="center"><img src="https://user-images.githubusercontent.com/13858689/76443427-ac13b780-63c2-11ea-84c0-d6612fb95165.png" /></p>
<!-- <p align="center"><img width="220px" src="https://upload.wikimedia.org/wikipedia/commons/e/e8/Generic_Feed-icon.png"/></p> -->
<h3 align="center">:pushpin::newspaper: Feed-Box</h3>

<p align="center">Update a pinned gist with an RSS/Atom feed</p>

---

[![license](https://img.shields.io/github/license/mashape/apistatus.svg)](https://github.com/albertocc/feed-box/blob/master/LICENSE)
![Feed-Box](https://github.com/albertocc/feed-box/workflows/Update%20a%20pinned%20gist%20with%20an%20RSS/Atom%20feed/badge.svg?branch=master)

**Feed-Box** is a simple **GitHub action** to update a public gist with the latest entries from any RSS/Atom feed

## Setup

### Prep work

1. Create a new public GitHub Gist (https://gist.github.com/)  
1. Create a token with the `gist` scope and copy it. (https://github.com/settings/tokens/new)  

### Project setup

1. Fork this repo  
1. Edit the [environment variables](https://github.com/albertocc/feed-box/blob/master/.github/workflows/main.yml#L13-L15) in `.github/workflows/main.yml`:
   - **GIST_ID:** The ID portion from your gist url:  
   `https://gist.github.com/username/`**`05c75f4491d78792c767ac8bc07d7e46`**  
   - **RSS_URL:** The URL of the RSS/Atom feed you want to use:  
   **`'https://en.wikinews.org/w/index.php?title=Special:NewsFeed&feed=atom'`**  
   - You can also set in this file how often you want to update the gist. By default it's updated once a day:  
   `cron:`**`"0 0 * * * *"`**
1. Go to the repo **Settings > Secrets**
1. Add the following environment variable:
   - **GH_TOKEN:** The GitHub token generated above.

## Credits

- [rss-parser](https://github.com/rbren/rss-parser)
- [gist-box](https://github.com/JasonEtco/gist-box)
- Inspired by the super [Awesome Pinned Gists](https://github.com/matchai/awesome-pinned-gists) projects

### License

[MIT License](https://github.com/albertocc/feed-box/blob/master/LICENSE) - Copyrights (c) 2020 - [Alberto Cabeza Cardiel](http://alberto.cc)
