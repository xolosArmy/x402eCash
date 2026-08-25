document.documentElement.classList.add('js')

const toggle = document.querySelector('[data-nav-toggle]')
const nav = document.querySelector('[data-nav]')

if (toggle && nav) {
  const closeNav = () => {
    toggle.setAttribute('aria-expanded', 'false')
    nav.removeAttribute('data-open')
  }

  toggle.addEventListener('click', () => {
    const isOpen = toggle.getAttribute('aria-expanded') === 'true'
    toggle.setAttribute('aria-expanded', String(!isOpen))
    if (isOpen) nav.removeAttribute('data-open')
    else nav.setAttribute('data-open', '')
  })

  nav.addEventListener('click', (event) => {
    if (event.target.closest('a')) closeNav()
  })

  window.addEventListener('resize', () => {
    if (window.innerWidth > 820) closeNav()
  })
}

if ('IntersectionObserver' in window) {
  const links = new Map(
    [...document.querySelectorAll('[data-nav] a[href^="#"]')]
      .map((link) => [link.getAttribute('href').slice(1), link])
  )
  const sections = [...links.keys()]
    .map((id) => document.getElementById(id))
    .filter(Boolean)

  const observer = new IntersectionObserver((entries) => {
    const visible = entries
      .filter((entry) => entry.isIntersecting)
      .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0]
    if (!visible) return
    for (const link of links.values()) link.removeAttribute('aria-current')
    links.get(visible.target.id)?.setAttribute('aria-current', 'location')
  }, { rootMargin: '-20% 0px -70% 0px', threshold: [0, 0.25, 0.5] })

  sections.forEach((section) => observer.observe(section))
}
