var sequenceDiagram = (this && this.sequenceDiagram) || {};
(function (api) {
	var handledCounts = [2, 3, 4, 5, 6, 9, 11, 12, 13, 14, 15, 16, 20];

	function Diagram() {
		this.currentAgents = [];
		this.events = [this.currentAgents];
		this.activeGroups = 0;
	}
	Diagram.prototype = {
		setAgents: function (agents, fullNames) {
			if (this.events[this.events.length - 1] === this.currentAgents) {
				this.events.pop();
			}
			this.currentAgents = agents;
			this.events.push(agents);
			agents.fullNames = fullNames || {};
		},
		startSection: function () {
			this.events.push({section: 'start'});
		},
		stopSection: function () {
			this.events.push({section: 'stop'});
		},
		addTitle: function (html) {
			this.events.push(html);
		},
		startGroup: function (who, label) {
			if (this.currentAgents.indexOf(who) === -1) {
				this.currentAgents.push(who);
			}
			this.events.push({group: who, label: label});
			this.activeGroups++;
		},
		stopGroup: function () {
			this.events.push({group: false});
			this.activeGroups--;
		},
		finish: function () {
			while (this.activeGroups > 0) {
				this.stopGroup();
			}
			return this;
		},
		addAction: function (from, to, label, myclass) {
			if (this.currentAgents.indexOf(from) === -1) {
				this.currentAgents.push(from);
			}
			if (this.currentAgents.indexOf(to) === -1) {
				this.currentAgents.push(to);
			}
			this.events.push({from: from, to: to, label: label, myclass: myclass});
		},
		addEvent: function (left, right, label, type) {
			if (this.currentAgents.indexOf(left) === -1) {
				this.currentAgents.push(left);
			}
			if (this.currentAgents.indexOf(right) === -1) {
				this.currentAgents.push(right);
			}
			this.events.push({left: left, right: right, label: label, type: type || 'event'});
		},
		columnCounts: function () {
			var counts = [];
			for (var i = 0; i < this.events.length; i++) {
				var event = this.events[i];
				if (Array.isArray(event)) {
					var agentCount = event.length;
					while (handledCounts.indexOf(agentCount) === -1 && agentCount < handledCounts[handledCounts.length - 1]) {
						agentCount++;
					}
					if (counts.indexOf(agentCount) === -1) {
						counts.push(agentCount);
					}
				}
			}
			return counts;
		},
		generateCss: function () {
			var css = "";
			var columnCounts = this.columnCounts();
			for (var i = 0; i < columnCounts.length; i++) {
				css += '\n\n' + api.generateCss(columnCounts[i]);
			}
			return css;
		},
		toHtml: function () {
			var html = ['<div class="sequence-diagram-layout">']
			var haveHead = false, haveContent = false, inBody = false;
			var agents = [], agentCount = 0;
			var indent = '\t\t';
			var events = this.events.slice(0);
			for (var eventNum = 0; eventNum < events.length; eventNum++) {
				var event = events[eventNum];
				if (Array.isArray(event)) {
					agents = event;
					agentCount = agents.length;
					while (handledCounts.indexOf(agentCount) === -1 && agentCount < handledCounts[handledCounts.length - 1]) {
						agentCount++;
					}
					agentCount = Math.min(agentCount, handledCounts[handledCounts.length - 1]);
					if (inBody) {
						html.push('\t</div>');
					}

                    // Genus (agent groupings), must appear before the headers so they extend to the bottom of the diagram
					//html.push('<div class="entity left-2-9 right-3-9" style="top: 0; bottom: 0; background: lightgrey; padding-top: 0.5em">Expressway-E</div>');
					//html.push('<div class="entity left-4-9 right-6-9" style="top: 0; bottom: 0; background: lightgrey; padding-top: 0.5em">Expressway-C</div>')

					html.push('\t<div class="header">');
					for (var i = 0; i < agentCount; i++) {
						if (agents[i]) {
							html.push(indent + '<div class="entity col-' + (i + 1) + '-' + agentCount + '">' + escapeHtml(agents.fullNames[agents[i]] || agents[i]) + '</div>');
						}
					}
					html.push('\t</div>');
					html.push('\t<div class="body">');
					for (var i = 0; i < agentCount; i++) {
						if (agents[i]) {
							html.push(indent + '<div class="line left-' + (i + 1) + '-' + agentCount + '"></div>');
						}
					}
					html.push('');
					inBody = true;
					haveContent = false;
				} else {
					if (!inBody) {
						html.push('\t<div class="body">');
					}
					inBody = true;
					if (typeof event === 'string') {
						html.push('');
						if (haveContent) {
							html.push(indent + '<hr>');
						}
						if (event) {
							html.push(indent + '<div class="section-title">' + event + '</div>');
						}
						html.push('');
					} else if (event.section === 'start') {
						html.push('<div class="section">');
						indent += '\t';
						haveContent = false;
						continue;
					} else if (event.section === 'stop') {
						html.push('</div>');
						indent = indent.replace(/\t$/, '');
					} else if (event.group) {
						var ownerPos = agents.indexOf(event.group) + 1;
						html.push(indent + '<div class="group">');
						indent += '\t';
						html.push(indent + '<div class="lifeline left-' + ownerPos + '-' + agentCount + '">' + (event.label || '') + '</div>');
					} else if (event.group === false) {
						indent = indent.replace(/\t$/, '');
						html.push(indent + '</div>');
					} else if (event.from && event.to) {
						var fromPos = agents.indexOf(event.from) + 1;
						var toPos = agents.indexOf(event.to) + 1;
						if (fromPos < toPos) {
							var alt = event.from + ' --> ' + event.to;
							html.push(indent + '<div class="action left-' + fromPos + '-' + agentCount + ' right-' + toPos + '-' + agentCount + ' ' + (event.myclass || '') + '">'
								+ '<div class="arrow" title="' + escapeHtml(alt) + '">' + lineImages.right + '</div>'
								+ (event.label || '')
								+ '</div>');
						} else if (fromPos > toPos) {
							var alt = event.to + ' <-- ' + event.from;
							html.push(indent + '<div class="action left-' + toPos + '-' + agentCount + ' right-' + fromPos + '-' + agentCount + ' ' + (event.myclass || '') + '">'
								+ '<div class="arrow" title="' + escapeHtml(alt) + '">' + lineImages.left + '</div>'
								+ (event.label || '')
								+ '</div>');
						} else {
							throw new Error('Self-signals not supported yet');
						}
					} else if (event.left && event.right) {
						var leftPos = agents.indexOf(event.left) + 1;
						var rightPos = agents.indexOf(event.right) + 1;
						if (leftPos > rightPos) {
							var tmp = leftPos;
							leftPos = rightPos, rightPos = tmp;
						}
						if (leftPos === rightPos) {
							html.push(indent + '<div class="' + event.type + ' col-' + leftPos + '-' + agentCount + '">' + (event.label || '') + '</div>');
						} else {
							html.push(indent + '<div class="' + event.type + ' left-' + leftPos + '-' + agentCount + ' right-' + rightPos + '-' + agentCount + '">'
							+ (event.label || '')
							+ '</div>');
						}
					} else if (event.left === null && event.right === null) {
							html.push(indent + '<div class="' + event.type + '">'
							+ (event.label || '')
							+ '</div>');
					} else {
						throw new Error('Unknown event: ' + JSON.stringify(event));
					}
					haveContent = true;
				}
			}
			if (inBody) {
				html.push('\t</div>');
			}
			html.push('</div>');
			return html.join('\n');
		}
	};
	
	function escapeHtml(str) {
		return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
	}
	
	function strip(str) {
		return str.replace(/^[ \t\r\n]*/, '').replace(/[ \t\r\n]*$/, '');
	}
	
	function splitStr(line, splitChar, stripParts) {
		var parts = [];
		var nextPart = "";
		for (var i = 0; i < line.length; i++) {
			var c = line.charAt(i);
			if (c === '\\') {
				nextPart += c + line.charAt(++i);
			} else if (c === splitChar) {
				parts.push(stripParts ? strip(nextPart) : nextPart);
				nextPart = "";
			} else {
				nextPart += c;
			}
		}
		parts.push(stripParts ? strip(nextPart) : nextPart);
		return parts;
	}
	
	var lineImages = {
		left: '<svg width="100%" height="14" preserveAspectRatio="xMinYMid slice" viewBox="0 0 1400 14"><polygon points="0,7 15,1 10,6 1400,6 1400,8 10,8 15,13 0,7"/></svg>',
		right: '<svg width="100%" height="14" preserveAspectRatio="xMaxYMid slice" viewBox="0 0 1400 14"><polygon points="1400,7 1385,1 1390,6 0,6 0,8 1390,8 1385,13 1400,7"/></svg>'
	};

	function hasClass(element, cssClass, orTagName) {
		var padded = " " + element.className + " ";
		return (padded.indexOf(" " + cssClass + " ") !== -1) || (orTagName && (element.tagName + "").toLowerCase() == cssClass.toLowerCase());
	}
	
	function walkNodes(element, beforeCallback, afterCallback) {
		if (beforeCallback && beforeCallback(element) !== false) {
			if (element.nodeType === 1) {
				for (var i = 0; i < element.childNodes.length; i++) {
					walkNodes(element.childNodes[i], beforeCallback, afterCallback);
				}
			}
		}
		if (afterCallback) {
			afterCallback(element);
		}
	}
	
	function textContent(element) {
		return element.textContent || element.innerText || '';
	}

	function percentage(ratio) {
		return (Math.round(ratio*1000)/10) + '%';
	}
	api.generateCss = function (columnCount) {
		var css = [];
		for (var pos = 0; pos < columnCount; pos++) {
			css.push('.col-' + (pos + 1) + '-' + columnCount + ' {');
			css.push('	margin-left: ' + percentage(pos/columnCount) + ';');
			css.push('	margin-right: ' + percentage((columnCount - pos - 1)/columnCount));
			css.push('}');
			css.push('.left-' + (pos + 1) + '-' + columnCount + ' {');
			css.push('	margin-left: ' + percentage((pos + 0.5)/columnCount));
			css.push('}');
			css.push('.right-' + (pos + 1) + '-' + columnCount + ' {');
			css.push('	margin-right: ' + percentage((columnCount - pos - 0.5)/columnCount));
			css.push('}');
		}

        // Bud - classes to use for an agent heading that spans multiple columns. These are for Expressway-C.
        //       Use span-3-5 and span-7-9 if only one phone on the left, use span-4-6 and span-8-10 if 2 phones
        //       on the left.
        css.push('.span-3-5 {');
        css.push('  margin-left: ' + percentage(2/columnCount) + ';');
        css.push('  margin-right: ' + percentage((columnCount - 5)/columnCount) + ';');
        css.push('}');
        css.push('.span-7-9 {');
        css.push('  margin-left: ' + percentage(6/columnCount) + ';');
        css.push('  margin-right: ' + percentage((columnCount - 9)/columnCount) + ';');
        css.push('}');
        css.push('.span-4-6 {');
        css.push('  margin-left: ' + percentage(3/columnCount) + ';');
        css.push('  margin-right: ' + percentage((columnCount - 6)/columnCount) + ';');
        css.push('}');
        css.push('.span-8-10 {');
        css.push('  margin-left: ' + percentage(7/columnCount) + ';');
        css.push('  margin-right: ' + percentage((columnCount - 10)/columnCount) + ';');
        css.push('}');
		return css.join([]);
	};
	api.fromElement = function (element) {
		if (hasClass(element, 'sequence-diagram-layout', true)) {
			// Already formatted
			return null;
		} else if (hasClass(element, 'sequence-diagram-semantic', true)) {
			return this.fromSemantic(element);
		} else if (hasClass(element, 'sequence-diagram-text', true)) {
			return this.fromText(textContent(element));
		}
		return null;
	};
	api.fromSemantic = function (element) {
		var diagram = new Diagram();
		var genus, genusNames, entities, entityNames, elementContent, fromEntity, toEntity, groupPending = false, sectionPending = false;

		function startGroupIfNeeded(label) {
			if (groupPending) {
				groupPending = false;
				var entity = fromEntity || toEntity;
				diagram.startGroup(entity, label || '?');
			}
		}
		
		walkNodes(element, function (node) {
			if (hasClass(node, 'header', true)) {
				entities = [];
				entityNames = {};
			} else if (hasClass(node, 'entity', true)) {
				var name = textContent(node);
				var alias = node.getAttribute('alias') || name;
				entities.push(alias);
				entityNames[alias] = name;
				return false;
			} else if (hasClass(node, 'genus', true)) {
				var name = textContent(node);
				var alias = node.getAttribute('alias') || name;
				genus.push(alias);
				genusNames[alias] = name;
				return false;
			} else if (hasClass(node, 'action', true)) {
				startGroupIfNeeded();
				elementContent = node.innerHTML;
				fromEntity = node.getAttribute('from') || node.getAttribute('for') || '?';
				toEntity = node.getAttribute('to') || node.getAttribute('for') || '??';
				myclass = node.getAttribute('class') || '';
			} else if (hasClass(node, 'lifeline', true)) {
				elementContent = node.innerHTML;
				fromEntity = null;
				toEntity = null;
			} else if (hasClass(node, 'note', true) || hasClass(node, 'event', true)) {
				startGroupIfNeeded();
				elementContent = node.innerHTML;
				fromEntity = node.getAttribute('from') || node.getAttribute('for');
				toEntity = node.getAttribute('to') || node.getAttribute('for');
			} else if (hasClass(node, 'section', true)) {
				diagram.startSection();
			} else if (hasClass(node, 'title', true)) {
				diagram.addTitle(node.innerHTML);
			} else if (hasClass(node, 'group', true)) {
				groupPending = true;
				fromEntity = '?';
				toEntity = '??';
			} else if (hasClass(node, 'for', true)) {
				fromEntity = toEntity = textContent(node);
			} else if (hasClass(node, 'from', true)) {
				fromEntity = textContent(node);
			} else if (hasClass(node, 'to', true)) {
				toEntity = textContent(node);
			}
		}, function (node) {
			if (hasClass(node, 'header', true)) {
				diagram.setAgents(entities, entityNames);
			} else if (hasClass(node, 'action', true)) {
				diagram.addAction(fromEntity, toEntity, elementContent, myclass);
			} else if (hasClass(node, 'note', true)) {
				diagram.addEvent(fromEntity || toEntity, toEntity || fromEntity, elementContent, 'note');
			} else if (hasClass(node, 'event', true)) {
				diagram.addEvent(fromEntity || toEntity, toEntity || fromEntity, elementContent, 'event');
			} else if (hasClass(node, 'lifeline', true)) {
				startGroupIfNeeded(elementContent);
			} else if (hasClass(node, 'section', true)) {
				diagram.stopSection();
			} else if (hasClass(node, 'group', true)) {
				if (!groupPending) {
					diagram.stopGroup();
				}
				groupPending = false;
			}
		});
		return diagram;
	};
	api.fromText = function (text) {
		var lines = text.split('\n');
		var diagram = new Diagram();
		var indents = [];
		for (var i = 0; i < lines.length; i++) {
			var stripped = strip(lines[i]);
			var parts = splitStr(stripped, ':', false);
			// Close groups until indent found
			while (stripped && indents.length && lines[i].substring(0, indents[0].length) !== indents[0]) {
				diagram.stopGroup();
				indents.shift();
			}
			if (/^(--+|\/\/)/.test(stripped)) {
				var label = stripped.replace(/^(--+|\/\/)/, '');
				diagram.addTitle(escapeHtml(label));
			} else if (parts.length === 1) {
				parts[0] = strip(parts[0]);
				if (parts[0]) {
					var names = splitStr(parts[0], ',', true);
					if (names.length > 1) {
						diagram.setAgents(names);
					} else {
						var type = 'event';
						var remainder = escapeHtml(strip(names[0]));
						if (/^\(.+\)$/.test(remainder)) {
							type = 'note';
							remainder = remainder.replace(/^\(/, '').replace(/\)$/, '');
						}
						diagram.addEvent(null, null, remainder, type);
					}
				}
			} else {
				var who = strip(parts[0]), whoParts;
				var thisIndent = lines[i].match(/^[ \t]*/)[0];
				var nextIndent = (lines[i + 1] || '').match(/^[ \t]*/)[0];
				var remainder = escapeHtml(parts.slice(1).join(':'));
				if ((whoParts = who.split(/-+>/)).length > 1) {
					diagram.addAction(strip(whoParts[0]), strip(whoParts[1]), remainder);
				} else if ((whoParts = who.split(/<-+/)).length > 1) {
					diagram.addAction(strip(whoParts[1]), strip(whoParts[0]), remainder);
				} else {
					var type = 'event';
					remainder = strip(remainder);
					if (/^\(.+\)$/.test(remainder)) {
						type = 'note';
						remainder = remainder.replace(/^\(/, '').replace(/\)$/, '');
					}
					if ((whoParts = who.split(/--+/)).length > 1) {
						diagram.addEvent(strip(whoParts[0]), strip(whoParts[1]), remainder, type);
					} else if (nextIndent.substring(0, thisIndent.length) === thisIndent && nextIndent !== thisIndent) {
						diagram.startGroup(who, remainder);
						indents.unshift(nextIndent);
					} else {
						diagram.addEvent(who, who, remainder, type);
					}
				}
			}
		}
		diagram.finish();
		return diagram;
	};
	api.textToHtml = function (text) {
		var diagram = this.fromText(text);
		return diagram.toHtml();
	};
	api.setLines = function (leftImg, rightImg) {
		lineImages.left = leftImg;
		lineImages.right = rightImg;
	};
	api.convert = function (element) {
    	// Bud - moved columnsCssDone initialization inside of api.convert() so it gets cleared out each time the
    	//       sequence diagram and regenerated. This ensures the style elements are replaced each time in case
    	//       the number of columns changed (e.g. includeTurn).
    	var columnsCssDone = {};
		element = element || document.body;
		walkNodes(element, function (node) {
			if (node.style && node.style.display === 'none') {
				return false;
			}
			var diagram = api.fromElement(node);
			if (diagram) {
				var element = document.createElement('div');
				element.className = 'sequence-diagram-replacement';
				element.innerHTML = diagram.toHtml();

				var columnCounts = diagram.columnCounts();
				for (var i = 0; i < columnCounts.length; i++) {
					var columnCount = columnCounts[i];
					if (!columnsCssDone[columnCount]) {
						columnsCssDone[columnCount] = true;
						var css = api.generateCss(columnCount);
						var style = document.getElementById("seqStyle");
                        if (!style) {
    						style = document.createElement('style');
	    					style.id = 'seqStyle'
    						document.head.appendChild(style);
	    				}
						style.innerHTML = css;
					}
				}

				node.style.display = 'none';
				node.parentNode.insertBefore(element, node);
				return false;
			}
		});
	};
	
	if (typeof window !== 'undefined' && typeof document !== 'undefined') {
		window.addEventListener('load', function () {
			api.convert(document.body);
		});
	}
})(sequenceDiagram);