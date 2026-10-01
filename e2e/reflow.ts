import { expect, type Page } from '@playwright/test'

/**
 * WCAG 1.4.10 reflow: the DOCUMENT must not scroll sideways.
 *
 * Wide content inside an `overflow-x: auto` scroller is fine — it scrolls
 * there and the page does not. The assertion is on the document's own scroll
 * width; the element search afterwards exists only to name a culprit.
 *
 * A `position: absolute` box is clipped by a scroller only when that scroller
 * is (or contains) its containing block, so the walk that names a culprit
 * skips ancestors until it reaches the containing block.
 *
 * `body { overflow-x: hidden }` here propagates to the viewport, so a too-wide
 * column is CLIPPED rather than scrollable: the visitor cannot reach what is
 * past the edge at all. The document's scroll width still reports it, which
 * is what this asserts on.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement
    if (doc.scrollWidth <= doc.clientWidth) return null

    const clipped = (el: Element): boolean => {
      const pos = getComputedStyle(el).position
      if (pos === 'fixed') return false
      let needPositioned = pos === 'absolute'
      let n = el.parentElement
      while (n && n !== doc) {
        const style = getComputedStyle(n)
        if (needPositioned) {
          if (style.position === 'static') {
            n = n.parentElement
            continue
          }
          needPositioned = false
        }
        // body's overflow moves to the viewport when html's is visible, so
        // body does not clip anything itself.
        const propagated = n === document.body && getComputedStyle(doc).overflowX === 'visible'
        const ox = propagated ? 'visible' : style.overflowX
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true
        n = n.parentElement
      }
      return false
    }

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right)
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0]
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)'
    }
  })
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull()
}
