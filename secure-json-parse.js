// secure-json-parse.js (browser version)
(function () {
  'use strict';

  const suspectProtoRx = /"(?:_|\\u005[Ff])(?:_|\\u005[Ff])(?:p|\\u0070)(?:r|\\u0072)(?:o|\\u006[Ff])(?:t|\\u0074)(?:o|\\u006[Ff])(?:_|\\u005[Ff])(?:_|\\u005[Ff])"\s*:/;
  const suspectConstructorRx = /"(?:c|\\u0063)(?:o|\\u006[Ff])(?:n|\\u006[Ee])(?:s|\\u0073)(?:t|\\u0074)(?:r|\\u0072)(?:u|\\u0075)(?:c|\\u0063)(?:t|\\u0074)(?:o|\\u006[Ff])(?:r|\\u0072)"\s*:/;

  function filter(obj, { protoAction = 'error', constructorAction = 'error', safe } = {}) {
    let next = [obj];

    while (next.length) {
      const nodes = next;
      next = [];

      for (const node of nodes) {
        if (protoAction !== 'ignore' && Object.prototype.hasOwnProperty.call(node, '__proto__')) {
          if (safe === true) return null;
          if (protoAction === 'error') throw new SyntaxError('Object contains forbidden prototype property');
          delete node.__proto__;
        }

        if (
          constructorAction !== 'ignore' &&
          Object.prototype.hasOwnProperty.call(node, 'constructor') &&
          node.constructor !== null &&
          typeof node.constructor === 'object' &&
          Object.prototype.hasOwnProperty.call(node.constructor, 'prototype')
        ) {
          if (safe === true) return null;
          if (constructorAction === 'error') throw new SyntaxError('Object contains forbidden prototype property');
          delete node.constructor;
        }

        for (const key in node) {
          const value = node[key];
          if (value && typeof value === 'object') next.push(value);
        }
      }
    }
    return obj;
  }

  function _parse(text, reviver, options) {
    if (options == null && reviver && typeof reviver === 'object') {
      options = reviver;
      reviver = undefined;
    }

    if (text && text.charCodeAt && text.charCodeAt(0) === 0xFEFF) {
      text = text.slice(1);
    }

    const obj = JSON.parse(text, reviver);

    if (obj === null || typeof obj !== 'object') return obj;

    const protoAction = (options && options.protoAction) || 'error';
    const constructorAction = (options && options.constructorAction) || 'error';

    if (protoAction === 'ignore' && constructorAction === 'ignore') return obj;

    if (protoAction !== 'ignore' && constructorAction !== 'ignore') {
      if (!suspectProtoRx.test(text) && !suspectConstructorRx.test(text)) return obj;
    } else if (protoAction !== 'ignore') {
      if (!suspectProtoRx.test(text)) return obj;
    } else {
      if (!suspectConstructorRx.test(text)) return obj;
    }

    return filter(obj, { protoAction, constructorAction, safe: options && options.safe });
  }

  function safeParse(text, reviver) {
    try {
      return _parse(text, reviver, { safe: true });
    } catch {
      return undefined;
    }
  }

  // expose globally
  window.secureParse = safeParse;

})();

