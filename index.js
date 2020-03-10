const { GistBox } = require('gist-box')
const Parser = require('rss-parser')
const parser = new Parser()
const maxLength = 40 // 55 per line
const { GH_TOKEN: token, GIST_ID: id, RSS_URL: url } = steps.env;

(async () => {
  const feed = await parser.parseURL(url)

  let content = ''
  feed.items.slice(0, 5).forEach(item => {
    content += `${trimTitle(item.title)} 📆 ${parseDate(item.pubDate)}\n`
  })

  const box = new GistBox({ id, token })
  await box.update({
    filename: feed.title,
    description: ':pencil: A new description',
    content: content
  })
  // console.log(feed.title)
  // feed.items.slice(0, 5).forEach(item => {
  //   console.log(`* ${trimTitle(item.title)} (${parseDate(item.pubDate)})`)
  // })
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
