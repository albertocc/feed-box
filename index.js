require('dotenv').config()
const { GistBox } = require('gist-box')
const Parser = require('rss-parser')
const parser = new Parser()
const maxLength = 38 // 55 per line
const { GH_TOKEN: token, GIST_ID: id, RSS_URL: url } = process.env;

(async () => {
  const feed = await parser.parseURL(url)

  let content = ''
  feed.items.slice(0, 5).forEach(item => {
    content += `• ${trimTitle(item.title)} 📆 ${parseDate(item.pubDate)}\n`;
  })

  const box = new GistBox({ id, token })
  await box.update({
    filename: `📰 ${feed.title}`,
    content: content
  })
})()

const parseDate = date => {
  return new Date(date).toLocaleString('default', {
    day: '2-digit',
    month: 'short',
    year: 'numeric'
  })
}

const trimTitle = string => {
  return string.length > maxLength
    ? (string.substring(0, maxLength - 3).trimEnd() + '...').padEnd(maxLength)
    : addSpaces(string)
}

const addSpaces = string => {
  return string.length < maxLength
    ? string + ' '.repeat(maxLength - string.length)
    : string
}
