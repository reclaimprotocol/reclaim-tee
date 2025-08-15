package providers

import (
	"fmt"
	"strings"

	"io"

	"github.com/antchfx/xpath"
	"golang.org/x/net/html"
)

// pNode is a positioned DOM node with byte offsets into the original HTML
// Start/End cover the full outer range (including start and end tags for elements)
// StartTagEnd is the end of the start tag token; EndTagStart is the start of the end tag token
// For self-closing tags: StartTagEnd == EndTagStart == End
// For text/comment nodes: StartTagEnd/EndTagStart are zero

type pNode struct {
	Type        html.NodeType
	Data        string
	Attrs       []html.Attribute
	Parent      *pNode
	Children    []*pNode
	Start       int
	End         int
	StartTagEnd int
	EndTagStart int
	NS          string // "" for html, or "svg"/"math" for foreign content
	Implied     bool   // true if this element was auto-inserted by HTML5 rules
}

// Insertion modes for HTML5 tree construction (only the ones we actually use)
type insertionMode int

const (
	initialMode insertionMode = iota
	beforeHTMLMode
	beforeHeadMode
	inHeadMode
	afterHeadMode
	inBodyMode
	inTableMode
	inRowMode
	inCellMode
	inTemplateMode
	afterBodyMode
)

// Parser state for HTML5 tree construction
type parserState struct {
	mode                     insertionMode
	stack                    []*pNode
	activeFormattingElements []*pNode
	headElementPointer       *pNode
	formElementPointer       *pNode
}

// helper: returns lower-case tag name
func lc(b []byte) string { return strings.ToLower(string(b)) }

// guards and helpers for html5 tree construction nuances
func isRawText(tag string) bool {
	switch strings.ToLower(tag) {
	case "script", "style":
		return true
	default:
		return false
	}
}
func isRCData(tag string) bool {
	switch strings.ToLower(tag) {
	case "title", "textarea":
		return true
	default:
		return false
	}
}
func headAllowed(tag string) bool {
	switch strings.ToLower(tag) {
	case "base", "basefont", "bgsound", "link", "meta", "noframes", "script", "style", "template", "title", "noscript":
		return true
	default:
		return false
	}
}
func isVoidElement(tag string) bool {
	switch strings.ToLower(tag) {
	case "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr":
		return true
	default:
		return false
	}
}

func isFormattingElement(tag string) bool {
	switch strings.ToLower(tag) {
	case "a", "b", "big", "code", "em", "font", "i", "nobr", "s", "small", "strike", "strong", "tt", "u":
		return true
	default:
		return false
	}
}

func isSpecialElement(tag string) bool {
	switch strings.ToLower(tag) {
	case "address", "applet", "area", "article", "aside", "base", "basefont", "bgsound", "blockquote", "body", "br", "button", "caption", "center", "col", "colgroup", "dd", "details", "dir", "div", "dl", "dt", "embed", "fieldset", "figcaption", "figure", "footer", "form", "frame", "frameset", "h1", "h2", "h3", "h4", "h5", "h6", "head", "header", "hgroup", "hr", "html", "iframe", "img", "input", "keygen", "li", "link", "listing", "main", "marquee", "menu", "meta", "nav", "noembed", "noframes", "noscript", "object", "ol", "p", "param", "plaintext", "pre", "script", "section", "select", "source", "style", "summary", "table", "tbody", "td", "template", "textarea", "tfoot", "th", "thead", "title", "tr", "track", "ul", "wbr", "xmp":
		return true
	default:
		return false
	}
}

// HTML5-like auto-close rules (subset) to approximate jsdom repairs
func autoCloseForStart(incoming string, stack *[]*pNode, tokenStart, tokenEnd int) {
	if len(*stack) < 2 {
		return
	}
	top := (*stack)[len(*stack)-1]
	topName := strings.ToLower(top.Data)
	incoming = strings.ToLower(incoming)

	// rawtext/rcdata elements are not auto-closed by arbitrary starts
	if isRawText(topName) || isRCData(topName) {
		return
	}

	// head auto-closes when encountering elements not allowed in head
	if topName == "head" && !headAllowed(incoming) {
		top.EndTagStart = tokenStart
		top.End = tokenStart
		*stack = (*stack)[:len(*stack)-1]
		return
	}
	// a very small body rule: close body on a second body or html start
	if topName == "body" && (incoming == "body" || incoming == "html") {
		top.EndTagStart = tokenStart
		top.End = tokenStart
		*stack = (*stack)[:len(*stack)-1]
		return
	}

	// p closes before many block-level starts
	if topName == "p" {
		if isBlockStarter(incoming) || incoming == "p" {
			top.EndTagStart = tokenStart
			top.End = tokenStart
			*stack = (*stack)[:len(*stack)-1]
			return
		}
	}
	// li closes on li
	if topName == "li" && incoming == "li" {
		top.EndTagStart = tokenStart
		top.End = tokenStart
		*stack = (*stack)[:len(*stack)-1]
		return
	}
	// dt/dd close on dt or dd respectively
	if (topName == "dt" && (incoming == "dt" || incoming == "dd")) ||
		(topName == "dd" && (incoming == "dt" || incoming == "dd")) {
		top.EndTagStart = tokenStart
		top.End = tokenStart
		*stack = (*stack)[:len(*stack)-1]
		return
	}
	// option closes on option or optgroup; optgroup closes on optgroup
	if topName == "option" && (incoming == "option" || incoming == "optgroup") {
		top.EndTagStart = tokenStart
		top.End = tokenStart
		*stack = (*stack)[:len(*stack)-1]
		return
	}
	if topName == "optgroup" && incoming == "optgroup" {
		top.EndTagStart = tokenStart
		top.End = tokenStart
		*stack = (*stack)[:len(*stack)-1]
		return
	}
	// rp/rt close on rp/rt
	if (topName == "rp" && (incoming == "rp" || incoming == "rt")) ||
		(topName == "rt" && (incoming == "rp" || incoming == "rt")) {
		top.EndTagStart = tokenStart
		top.End = tokenStart
		*stack = (*stack)[:len(*stack)-1]
		return
	}
	// thead/tbody/tfoot close on each other
	if (topName == "thead" && (incoming == "tbody" || incoming == "tfoot")) ||
		(topName == "tbody" && (incoming == "thead" || incoming == "tfoot")) ||
		(topName == "tfoot" && (incoming == "thead" || incoming == "tbody")) {
		top.EndTagStart = tokenStart
		top.End = tokenStart
		*stack = (*stack)[:len(*stack)-1]
		return
	}
	// tr closes on tr
	if topName == "tr" && incoming == "tr" {
		top.EndTagStart = tokenStart
		top.End = tokenStart
		*stack = (*stack)[:len(*stack)-1]
		return
	}
	// td/th close on td/th
	if (topName == "td" && (incoming == "td" || incoming == "th")) ||
		(topName == "th" && (incoming == "td" || incoming == "th")) {
		top.EndTagStart = tokenStart
		top.End = tokenStart
		*stack = (*stack)[:len(*stack)-1]
		return
	}
	// colgroup closes on colgroup and on tbody/thead/tfoot/tr
	if topName == "colgroup" && (incoming == "colgroup" || incoming == "tbody" || incoming == "thead" || incoming == "tfoot" || incoming == "tr") {
		top.EndTagStart = tokenStart
		top.End = tokenStart
		*stack = (*stack)[:len(*stack)-1]
		return
	}
	// caption closes on table sections start or another caption
	if topName == "caption" && (incoming == "tbody" || incoming == "thead" || incoming == "tfoot" || incoming == "tr" || incoming == "caption") {
		top.EndTagStart = tokenStart
		top.End = tokenStart
		*stack = (*stack)[:len(*stack)-1]
		return
	}
}

func isBlockStarter(tag string) bool {
	switch tag {
	case "address", "article", "aside", "blockquote", "div", "dl", "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "main", "nav", "ol", "pre", "section", "table", "ul":
		return true
	default:
		return false
	}
}

// Insert implied tbody in table
func ensureTableBody(state *parserState, tokenStart int) {
	if len(state.stack) < 2 {
		return
	}

	parent := state.stack[len(state.stack)-1]
	if parent.Data != "table" {
		return
	}

	// Check if we already have tbody/thead/tfoot
	for _, child := range parent.Children {
		if child.Data == "tbody" || child.Data == "thead" || child.Data == "tfoot" {
			return
		}
	}

	// Create implied tbody with proper positioning
	tbodyEl := createImpliedElement("tbody", tokenStart, parent.NS)
	tbodyEl.Parent = parent
	parent.Children = append(parent.Children, tbodyEl)
	state.stack = append(state.stack, tbodyEl)
}

// Improved implied element creation with better positioning
func createImpliedElement(tag string, insertPos int, ns string) *pNode {
	return &pNode{
		Type:        html.ElementNode,
		Data:        tag,
		Start:       insertPos,
		End:         insertPos, // Will be updated when closed
		StartTagEnd: insertPos,
		EndTagStart: insertPos, // Will be updated when closed
		NS:          ns,
		Implied:     true,
	}
}

// Insert implied elements according to HTML5 rules
func ensureHTMLStructure(state *parserState, tokenStart int) {
	// Ensure we have html element
	if len(state.stack) == 1 {
		htmlEl := createImpliedElement("html", tokenStart, "")
		htmlEl.Parent = state.stack[0]
		state.stack[0].Children = append(state.stack[0].Children, htmlEl)
		state.stack = append(state.stack, htmlEl)
	}

	// Check if we need head or body
	htmlEl := state.stack[1]
	hasHead := false
	hasBody := false
	for _, child := range htmlEl.Children {
		if child.Data == "head" {
			hasHead = true
		}
		if child.Data == "body" {
			hasBody = true
		}
	}

	// If we need head and don't have it
	if !hasHead && state.mode == beforeHeadMode {
		headEl := createImpliedElement("head", tokenStart, "")
		headEl.Parent = htmlEl
		htmlEl.Children = append(htmlEl.Children, headEl)
		state.stack = append(state.stack, headEl)
		state.headElementPointer = headEl
		state.mode = inHeadMode
	}

	// If we need body and don't have it
	if !hasBody && (state.mode == afterHeadMode || state.mode == inBodyMode) {
		bodyEl := createImpliedElement("body", tokenStart, "")
		bodyEl.Parent = htmlEl
		htmlEl.Children = append(htmlEl.Children, bodyEl)
		state.stack = append(state.stack, bodyEl)
		state.mode = inBodyMode
	}
}

// Run adoption agency for all active formatting elements when a block closes
func runAdoptionAgencyForBlock(state *parserState, blockStartPos, blockEndPos int) {
	// Get the block element that just closed
	if len(state.stack) == 0 {
		return
	}

	// Find the parent where we should insert continuation elements (usually body)
	var insertParent *pNode
	for i := len(state.stack) - 1; i >= 0; i-- {
		if state.stack[i].Data == "body" {
			insertParent = state.stack[i]
			break
		}
	}
	if insertParent == nil && len(state.stack) > 0 {
		insertParent = state.stack[len(state.stack)-1] // Fallback to current parent
	}

	// Process active formatting elements to create continuation elements
	// Track which elements we've already processed to avoid duplicates
	processedElements := make(map[*pNode]bool)
	continuationElements := make([]*pNode, 0)
	var currentParent *pNode = insertParent

	// Process from innermost to outermost (reverse order) to maintain correct nesting
	// The last element in activeFormattingElements is the innermost
	for i := len(state.activeFormattingElements) - 1; i >= 0; i-- {
		fmtElement := state.activeFormattingElements[i]
		if fmtElement == nil {
			continue
		}

		// Skip if we've already processed this element
		if processedElements[fmtElement] {
			continue
		}
		processedElements[fmtElement] = true

		// Close the original formatting element at the block boundary
		if fmtElement.EndTagStart == 0 || fmtElement.EndTagStart > blockStartPos {
			fmtElement.EndTagStart = blockStartPos
			fmtElement.End = blockStartPos
		}

		// Create a continuation element that spans from the original start position
		continuation := &pNode{
			Type:        fmtElement.Type,
			Data:        fmtElement.Data,
			Attrs:       append([]html.Attribute{}, fmtElement.Attrs...), // Deep copy
			NS:          fmtElement.NS,
			Start:       fmtElement.Start,       // Start from original position (like jsdom)
			StartTagEnd: fmtElement.StartTagEnd, // Preserve original tag end
			EndTagStart: blockEndPos,            // Will be extended as content is added
			End:         blockEndPos,            // Will be extended as content is added
			Parent:      currentParent,
		}

		// Add the continuation to its parent
		if currentParent != nil {
			currentParent.Children = append(currentParent.Children, continuation)
		}

		continuationElements = append(continuationElements, continuation)

		// Next (inner) element should be nested inside this one
		currentParent = continuation
	}

	// Clear active formatting elements and replace with continuations in original order
	state.activeFormattingElements = state.activeFormattingElements[:0]
	// Add continuations in reverse order so outermost is first in active list
	for i := len(continuationElements) - 1; i >= 0; i-- {
		elem := continuationElements[i]
		state.activeFormattingElements = append(state.activeFormattingElements, elem)
		// Add to stack so subsequent content goes inside the innermost element
	}
	// Add to stack in forward order so innermost is at top of stack
	for _, elem := range continuationElements {
		state.stack = append(state.stack, elem)
	}
}

// updateDescendantAdoptionElements recursively updates adoption agency continuation elements
func updateDescendantAdoptionElements(node *pNode, tokenEnd int) {
	if node == nil {
		return
	}

	for _, child := range node.Children {
		if child.Type == html.ElementNode && child.EndTagStart < tokenEnd {
			// Only extend if this looks like an adoption agency continuation
			// These elements should have:
			// 1. EndTagStart > StartTagEnd (set to a block boundary position)
			// 2. Start < StartTagEnd (starts before their own start tag - impossible except for reconstructed elements)
			if child.EndTagStart > child.StartTagEnd && child.Start < child.StartTagEnd {
				child.EndTagStart = tokenEnd
				child.End = tokenEnd
			}
		}
		// Recursively update descendants
		updateDescendantAdoptionElements(child, tokenEnd)
	}
}

// foster parenting insertion: insert node before nearest <table> ancestor in its parent's children
func fosterInsert(stack *[]*pNode, node *pNode) bool {
	for i := len(*stack) - 1; i >= 1; i-- {
		cur := (*stack)[i]
		if strings.ToLower(cur.Data) == "table" {
			parent := cur.Parent
			if parent == nil {
				return false
			}
			idx := -1
			for j, c := range parent.Children {
				if c == cur {
					idx = j
					break
				}
			}
			if idx == -1 {
				return false
			}
			node.Parent = parent
			parent.Children = append(parent.Children[:idx], append([]*pNode{node}, parent.Children[idx:]...)...)
			return true
		}
	}
	return false
}

// find foster parenting location (parent and index of table child)
func findFosterLocation(stack []*pNode) (parent *pNode, tableIdx int, ok bool) {
	for i := len(stack) - 1; i >= 1; i-- {
		cur := stack[i]
		if strings.ToLower(cur.Data) == "table" {
			p := cur.Parent
			if p == nil {
				return nil, 0, false
			}
			idx := -1
			for j, c := range p.Children {
				if c == cur {
					idx = j
					break
				}
			}
			if idx == -1 {
				return nil, 0, false
			}
			return p, idx, true
		}
	}
	return nil, 0, false
}

func nearestTableContextTag(stack []*pNode) string {
	for i := len(stack) - 1; i >= 1; i-- {
		s := strings.ToLower(stack[i].Data)
		switch s {
		case "table", "tbody", "thead", "tfoot", "tr", "td", "th":
			return s
		}
	}
	return ""
}

// parseHTMLWithOffsets builds a positioned node tree by streaming tokens and tracking cumulative offset.
func parseHTMLWithOffsets(src string) (*pNode, error) {
	z := NewPositionedTokenizer(strings.NewReader(src))
	doc := &pNode{Type: html.DocumentNode, Start: 0, End: len(src)}

	state := &parserState{
		mode:  beforeHTMLMode,
		stack: []*pNode{doc},
	}

tokenLoop:
	for {
		tt := z.Next()
		tokenStart, tokenEnd := z.TokenPosition()

		switch t := tt; t {
		case html.ErrorToken:
			if z.Err() == nil {
				// Close all open elements
				for len(state.stack) > 1 {
					cur := state.stack[len(state.stack)-1]
					cur.End = len(src)
					state.stack = state.stack[:len(state.stack)-1]
				}
				return doc, nil
			}
			if z.Err().Error() == "EOF" {
				for len(state.stack) > 1 {
					cur := state.stack[len(state.stack)-1]
					cur.End = len(src)
					state.stack = state.stack[:len(state.stack)-1]
				}
				return doc, nil
			}
			return nil, z.Err()

		case html.DoctypeToken:
			// Skip doctype, but update mode
			if state.mode == initialMode {
				state.mode = beforeHTMLMode
			}

		case html.StartTagToken:
			name, hasAttr := z.TagName()
			incoming := lc(name)

			// Ensure proper HTML structure
			if state.mode == beforeHTMLMode && incoming != "html" {
				ensureHTMLStructure(state, tokenStart)
				state.mode = afterHeadMode
			}
			if state.mode == beforeHeadMode && incoming != "head" && headAllowed(incoming) {
				ensureHTMLStructure(state, tokenStart)
			}
			if state.mode == afterHeadMode && incoming != "body" && !headAllowed(incoming) {
				ensureHTMLStructure(state, tokenStart)
			}

			// HTML5 rule: forms cannot be nested - ignore inner form start tags
			skipElement := false
			if incoming == "form" {
				for _, stackNode := range state.stack {
					if stackNode.Data == "form" {
						// Already inside a form, ignore this form start tag but continue processing
						skipElement = true
						break
					}
				}
			}

			if skipElement {
				// Skip creating the element but continue to next token
				continue tokenLoop
			}

			autoCloseForStart(incoming, &state.stack, tokenStart, tokenEnd)
			n := &pNode{Type: html.ElementNode, Data: incoming, Start: tokenStart, StartTagEnd: tokenEnd}

			// set namespace: inherit from parent, override at svg/math boundaries
			parent := state.stack[len(state.stack)-1]

			// Handle special insertion cases - ensure tbody before tr
			if incoming == "tr" && len(state.stack) > 1 {
				if parent.Data == "table" {
					// Create implied tbody for direct tr under table
					ensureTableBody(state, tokenStart)
					parent = state.stack[len(state.stack)-1] // Update parent to tbody
				}
			}

			n.NS = parent.NS
			if incoming == "svg" {
				n.NS = "svg"
			} else if incoming == "math" {
				n.NS = "math"
			}

			if hasAttr {
				var attrs []html.Attribute
				for {
					k, v, more := z.TagAttr()
					attrs = append(attrs, html.Attribute{Key: string(k), Val: string(v)})
					if !more {
						break
					}
				}
				n.Attrs = attrs
			}

			if isVoidElement(incoming) {
				n.EndTagStart = tokenEnd
				n.End = tokenEnd
				if inTableContext(state.stack) && !isTableAllowedInContext(incoming, state.stack) {
					_ = fosterInsert(&state.stack, n)
				} else {
					n.Parent = parent
					parent.Children = append(parent.Children, n)
				}
				break
			}

			// Update mode based on element
			switch incoming {
			case "html":
				state.mode = beforeHTMLMode
			case "head":
				state.mode = inHeadMode
				state.headElementPointer = n
			case "body":
				state.mode = inBodyMode
			case "table":
				state.mode = inTableMode
			case "tr":
				state.mode = inRowMode
			case "td", "th":
				state.mode = inCellMode
			case "template":
				// Template elements create an isolated context - their contents
				// are not accessible via normal XPath traversal (like jsdom)
				state.mode = inTemplateMode
			}

			if inTableContext(state.stack) && !isTableAllowedInContext(incoming, state.stack) {
				if !fosterInsert(&state.stack, n) {
					n.Parent = parent
					parent.Children = append(parent.Children, n)
				}
			} else {
				n.Parent = parent
				parent.Children = append(parent.Children, n)
				state.stack = append(state.stack, n)
			}

			// Track active formatting elements
			if isFormattingElement(incoming) {
				state.activeFormattingElements = append(state.activeFormattingElements, n)
			}

		case html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			n := &pNode{Type: html.ElementNode, Data: lc(name), Start: tokenStart, StartTagEnd: tokenEnd, EndTagStart: tokenStart, End: tokenEnd}
			parent := state.stack[len(state.stack)-1]
			n.NS = parent.NS
			switch n.Data {
			case "svg", "math":
				n.NS = n.Data
			}
			if hasAttr {
				var attrs []html.Attribute
				for {
					k, v, more := z.TagAttr()
					attrs = append(attrs, html.Attribute{Key: string(k), Val: string(v)})
					if !more {
						break
					}
				}
				n.Attrs = attrs
			}
			if inTableContext(state.stack) && !isTableAllowedInContext(n.Data, state.stack) {
				_ = fosterInsert(&state.stack, n)
			} else {
				n.Parent = parent
				parent.Children = append(parent.Children, n)
			}

		case html.EndTagToken:
			name, _ := z.TagName()
			tag := lc(name)

			// Don't run individual adoption agency here - let runAdoptionAgencyForBlock handle it
			// after the block is completely closed and we know the full structure

			for len(state.stack) > 1 {
				cur := state.stack[len(state.stack)-1]
				if strings.ToLower(cur.Data) == tag {
					cur.EndTagStart = tokenStart
					cur.End = tokenEnd

					// FIRST: Remove the element from the stack to ensure it's truly closed
					state.stack = state.stack[:len(state.stack)-1]

					// Update only adoption agency continuation elements when an end tag is processed
					// These are elements in the activeFormattingElements list
					for _, fmtElement := range state.activeFormattingElements {
						if fmtElement != nil && fmtElement.EndTagStart < tokenEnd {
							// Only extend if the element doesn't have a real end tag yet
							if fmtElement.EndTagStart > fmtElement.StartTagEnd {
								fmtElement.EndTagStart = tokenEnd
								fmtElement.End = tokenEnd

								// Also update any descendant adoption agency elements
								updateDescendantAdoptionElements(fmtElement, tokenEnd)
							}
						}
					}

					// THEN: Run adoption agency for unclosed formatting elements AFTER closing the block
					if isSpecialElement(tag) {
						runAdoptionAgencyForBlock(state, tokenStart, tokenEnd)
					}

					// Update mode when leaving certain elements
					switch tag {
					case "head":
						state.mode = afterHeadMode
					case "body":
						state.mode = afterBodyMode
					case "table":
						if len(state.stack) > 1 && state.stack[len(state.stack)-1].Data == "body" {
							state.mode = inBodyMode
						}
					}
					break
				}
				cur.EndTagStart = tokenStart
				cur.End = tokenStart
				state.stack = state.stack[:len(state.stack)-1]
			}

		case html.TextToken:
			text := string(z.Text())

			// Ensure proper structure for text in root
			if len(state.stack) == 1 {
				ensureHTMLStructure(state, tokenStart)
				ensureHTMLStructure(state, tokenStart) // Ensure body too
			}

			if inTableContext(state.stack) {
				if parent, idx, ok := findFosterLocation(state.stack); ok {
					// merge with previous text node at foster location if any
					if idx-1 >= 0 && parent.Children[idx-1].Type == html.TextNode {
						prev := parent.Children[idx-1]
						prev.End = tokenEnd
						prev.Data += text
					} else {
						t := &pNode{Type: html.TextNode, Data: text, Start: tokenStart, End: tokenEnd, Parent: parent}
						parent.Children = append(parent.Children[:idx], append([]*pNode{t}, parent.Children[idx:]...)...)
					}
					break
				}
			}
			t := &pNode{Type: html.TextNode, Data: text, Start: tokenStart, End: tokenEnd}
			parent := state.stack[len(state.stack)-1]
			t.Parent = parent
			parent.Children = append(parent.Children, t)

			// Extend parent element to include this text (important for adoption agency continuation elements)
			if parent.Type == html.ElementNode && parent.End < tokenEnd {
				parent.End = tokenEnd
				// For adoption agency continuation elements, update EndTagStart to include new content
				// These elements don't have a real end tag, so EndTagStart should move with content
				if parent.EndTagStart < parent.End {
					parent.EndTagStart = tokenEnd
				}

				// Also update all ancestor elements in case of nested adoption agency elements
				ancestor := parent.Parent
				for ancestor != nil && ancestor.Type == html.ElementNode {
					if ancestor.End < tokenEnd {
						ancestor.End = tokenEnd
						if ancestor.EndTagStart < ancestor.End {
							ancestor.EndTagStart = tokenEnd
						}
					}
					ancestor = ancestor.Parent
				}
			}

		case html.CommentToken:
			c := &pNode{Type: html.CommentNode, Data: string(z.Text()), Start: tokenStart, End: tokenEnd}
			if inTableContext(state.stack) {
				if !fosterInsert(&state.stack, c) {
					parent := state.stack[len(state.stack)-1]
					c.Parent = parent
					parent.Children = append(parent.Children, c)
				}
			} else {
				parent := state.stack[len(state.stack)-1]
				c.Parent = parent
				parent.Children = append(parent.Children, c)
			}
		}
	}
}

func inTableContext(stack []*pNode) bool {
	for i := len(stack) - 1; i >= 1; i-- {
		switch strings.ToLower(stack[i].Data) {
		case "table", "tbody", "thead", "tfoot", "tr", "td", "th":
			return true
		}
	}
	return false
}

func isTableAllowedInContext(incoming string, stack []*pNode) bool {
	ctx := nearestTableContextTag(stack)
	switch ctx {
	case "td", "th":
		// inside a cell, flow content allowed; accept nested table
		return true
	case "tr":
		return incoming == "td" || incoming == "th"
	case "tbody", "thead", "tfoot":
		return incoming == "tr"
	case "table":
		switch incoming {
		case "caption", "colgroup", "col", "tbody", "thead", "tfoot", "tr", "td", "th":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

// NodeNavigator implementation for antchfx/xpath

type pnav struct {
	root, cur *pNode
	attr      *html.Attribute
	attrIx    int
}

func (n *pnav) NodeType() xpath.NodeType {
	if n.attr != nil {
		return xpath.AttributeNode
	}
	switch n.cur.Type {
	case html.ElementNode:
		return xpath.ElementNode
	case html.TextNode:
		return xpath.TextNode
	case html.CommentNode:
		return xpath.CommentNode
	default:
		return xpath.RootNode
	}
}
func (n *pnav) LocalName() string {
	if n.attr != nil {
		return n.attr.Key
	}
	// Return the actual element name without namespace prefix
	// XPath queries like //svg should work regardless of namespace
	return n.cur.Data
}
func (n *pnav) Prefix() string { return "" }
func (n *pnav) Value() string {
	if n.attr != nil {
		return n.attr.Val
	}
	return n.cur.Data
}
func (n *pnav) Copy() xpath.NodeNavigator { cp := *n; return &cp }
func (n *pnav) MoveToRoot()               { n.cur = n.root; n.attr = nil; n.attrIx = -1 }
func (n *pnav) MoveToParent() bool {
	if n.attr != nil {
		n.attr = nil
		n.attrIx = -1
		return true
	}
	if n.cur.Parent == nil {
		return false
	}
	n.cur = n.cur.Parent
	return true
}
func (n *pnav) MoveToNext() bool {
	if n.attr != nil {
		return false
	}
	p := n.cur.Parent
	if p == nil {
		return false
	}
	idx := -1
	for i, c := range p.Children {
		if c == n.cur {
			idx = i
			break
		}
	}
	if idx >= 0 && idx+1 < len(p.Children) {
		n.cur = p.Children[idx+1]
		return true
	}
	return false
}
func (n *pnav) MoveToPrevious() bool {
	if n.attr != nil {
		return false
	}
	p := n.cur.Parent
	if p == nil {
		return false
	}
	idx := -1
	for i, c := range p.Children {
		if c == n.cur {
			idx = i
			break
		}
	}
	if idx > 0 {
		n.cur = p.Children[idx-1]
		return true
	}
	return false
}
func (n *pnav) MoveToChild() bool {
	if n.attr != nil {
		return false
	}
	if len(n.cur.Children) == 0 {
		return false
	}

	// Skip template content traversal to match jsdom behavior
	// Template contents are isolated in a separate document fragment
	if n.cur.Type == html.ElementNode && n.cur.Data == "template" {
		return false
	}

	n.cur = n.cur.Children[0]
	return true
}
func (n *pnav) MoveToFirst() bool { return n.MoveToChild() }
func (n *pnav) MoveToAttribute(ns, name string) bool {
	if n.cur.Type != html.ElementNode {
		return false
	}
	for i := range n.cur.Attrs {
		if n.cur.Attrs[i].Key == name {
			n.attr = &n.cur.Attrs[i]
			n.attrIx = i
			return true
		}
	}
	return false
}
func (n *pnav) MoveToNextAttribute() bool {
	if n.cur.Type != html.ElementNode || n.attr == nil {
		return false
	}
	next := n.attrIx + 1
	if next >= 0 && next < len(n.cur.Attrs) {
		n.attrIx = next
		n.attr = &n.cur.Attrs[next]
		return true
	}
	return false
}
func (n *pnav) MoveToNamespace(prefix string) bool { return false }
func (n *pnav) MoveToNextNamespace() bool          { return false }
func (n *pnav) MoveTo(ns xpath.NodeNavigator) bool {
	other, ok := ns.(*pnav)
	if !ok {
		return false
	}
	n.cur = other.cur
	n.attr = other.attr
	n.attrIx = other.attrIx
	return true
}

// positionedHTMLElements runs XPath and returns byte ranges for matches.
func positionedHTMLElements(htmlStr, xPath string, contentsOnly bool) ([]indexRange, error) {
	root, err := parseHTMLWithOffsets(htmlStr)
	if err != nil {
		return nil, err
	}
	n := &pnav{root: root, cur: root, attrIx: -1}
	x, err := xpath.Compile(xPath)
	if err != nil {
		return nil, err
	}
	iter := x.Select(n)
	var out []indexRange
	for iter.MoveNext() {
		curr := iter.Current().(*pnav).cur

		// Skip implied elements - jsdom doesn't provide byte locations for them
		if curr.Implied {
			continue
		}

		if contentsOnly && curr.Type == html.ElementNode {
			start := curr.StartTagEnd
			end := curr.EndTagStart
			if end < start {
				start = curr.StartTagEnd
				end = curr.End
			}
			out = append(out, indexRange{start: start, end: end})
		} else {
			out = append(out, indexRange{start: curr.Start, end: curr.End})
		}
	}
	return out, nil
}

// hook into existing helper
// TODO: add Abdule Lib
func extractHTMLElementsIndexes(html string, xpathExpression string, contentsOnly bool) ([]indexRange, error) {
	res, err := positionedHTMLElements(html, xpathExpression, contentsOnly)
	if err != nil {
		return nil, fmt.Errorf("Failed to find XPath: \"%s\"", xpathExpression)
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("Failed to find XPath: \"%s\"", xpathExpression)
	}
	return res, nil
}

// PositionedTokenizer is a stub to maintain compatibility with html_positioned.go
type PositionedTokenizer struct {
	*html.Tokenizer
	offset int
}

// NewPositionedTokenizer creates a new positioned tokenizer stub
func NewPositionedTokenizer(r io.Reader) *PositionedTokenizer {
	return &PositionedTokenizer{
		Tokenizer: html.NewTokenizer(r),
		offset:    0,
	}
}

// TokenPosition returns approximate token positions
func (pt *PositionedTokenizer) TokenPosition() (int, int) {
	raw := pt.Raw()
	start := pt.offset
	end := pt.offset + len(raw)
	pt.offset = end
	return start, end
}
