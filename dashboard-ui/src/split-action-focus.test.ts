// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest'
import type { MouseEvent as ReactMouseEvent } from 'react'
import { preserveSplitEditorMouseFocus } from './split-action-focus'

afterEach(() => { document.body.replaceChildren() })

function fixture(tag = 'input', type = 'text') {
  const dialog = document.createElement('section')
  dialog.setAttribute('role', 'dialog')
  const editor = document.createElement(tag) as HTMLInputElement
  if (tag === 'input') editor.type = type
  const button = document.createElement('button')
  dialog.append(editor, button)
  document.body.append(dialog)
  editor.focus()
  const preventDefault = vi.fn()
  const event = {
    currentTarget: button, button: 0, defaultPrevented: false,
    altKey: false, ctrlKey: false, metaKey: false, shiftKey: false, preventDefault,
  } as unknown as ReactMouseEvent<HTMLButtonElement>
  return { dialog, editor, button, event, preventDefault }
}

it.each(['text', 'search', 'email', 'url', 'tel', 'password'])('preserves a focused %s editor for primary mouse-down', type => {
  const { event, preventDefault, editor } = fixture('input', type)
  preserveSplitEditorMouseFocus(event, null)
  expect(preventDefault).toHaveBeenCalledOnce()
  expect(document.activeElement).toBe(editor)
})

it('preserves a textarea without moving focus or activating the button', () => {
  const { event, button, preventDefault } = fixture('textarea')
  const click = vi.fn()
  button.onclick = click
  preserveSplitEditorMouseFocus(event, null)
  expect(preventDefault).toHaveBeenCalledOnce()
  expect(click).not.toHaveBeenCalled()
})

it.each(['altKey', 'ctrlKey', 'metaKey', 'shiftKey', 'defaultPrevented'] as const)('does not intercept %s', key => {
  const { event, preventDefault } = fixture()
  preserveSplitEditorMouseFocus({ ...event, [key]: true }, null)
  expect(preventDefault).not.toHaveBeenCalled()
})

it.each([1, 2])('does not intercept mouse button %s', button => {
  const { event, preventDefault } = fixture()
  preserveSplitEditorMouseFocus({ ...event, button }, null)
  expect(preventDefault).not.toHaveBeenCalled()
})

it.each(['readonly', 'disabled-editor', 'disabled-action', 'outside-dialog', 'no-dialog', 'no-editor', 'composing'])('leaves %s on its existing focus path', state => {
  const { event, editor, button, dialog, preventDefault } = fixture()
  if (state === 'readonly') editor.readOnly = true
  if (state === 'disabled-editor') editor.disabled = true
  if (state === 'disabled-action') button.disabled = true
  if (state === 'outside-dialog') { document.body.append(editor); editor.focus() }
  if (state === 'no-dialog') dialog.removeAttribute('role')
  if (state === 'no-editor') button.focus()
  preserveSplitEditorMouseFocus(event, state === 'composing' ? editor : null)
  expect(preventDefault).not.toHaveBeenCalled()
})

it.each(['checkbox', 'number', 'range'])('does not interfere with %s control semantics', type => {
  const { event, preventDefault } = fixture('input', type)
  preserveSplitEditorMouseFocus(event, null)
  expect(preventDefault).not.toHaveBeenCalled()
})

it('does not intercept a select or a nested-dialog editor', () => {
  const select = fixture('select')
  preserveSplitEditorMouseFocus(select.event, null)
  expect(select.preventDefault).not.toHaveBeenCalled()
  const { event, editor, dialog, preventDefault } = fixture()
  const child = document.createElement('section')
  child.setAttribute('role', 'dialog')
  dialog.append(child)
  child.append(editor)
  editor.focus()
  preserveSplitEditorMouseFocus(event, null)
  expect(preventDefault).not.toHaveBeenCalled()
})
