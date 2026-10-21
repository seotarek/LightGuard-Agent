"""Zero-dependency Aho-Corasick Multi-Pattern Automaton.

Enables single-pass O(N + M) simultaneous matching of thousands of
adversarial prompt injection keywords, authority override terms,
and dangerous shell patterns without regex backtracking overhead.
"""

from collections import deque
from typing import Dict, List, Optional, Set, Tuple


class AhoCorasickNode:
    """Trie node with failure and output links."""

    def __init__(self) -> None:
        self.children: Dict[str, "AhoCorasickNode"] = {}
        self.fail: Optional["AhoCorasickNode"] = None
        self.output: Set[str] = set()


class FastPatternMatcher:
    """Multi-keyword search automaton operating in linear time."""

    def __init__(self, keywords: Optional[List[str]] = None) -> None:
        self.root = AhoCorasickNode()
        self._keywords_count = 0
        if keywords:
            self.build(keywords)

    def build(self, keywords: List[str]) -> None:
        """Construct trie and compute failure transitions."""
        self.root = AhoCorasickNode()
        self._keywords_count = len(keywords)

        # 1. Build standard trie
        for kw in keywords:
            kw_norm = kw.lower().strip()
            if not kw_norm:
                continue
            curr = self.root
            for ch in kw_norm:
                if ch not in curr.children:
                    curr.children[ch] = AhoCorasickNode()
                curr = curr.children[ch]
            curr.output.add(kw_norm)

        # 2. Compute failure links via BFS queue
        queue: deque[AhoCorasickNode] = deque()
        for ch, child in self.root.children.items():
            child.fail = self.root
            queue.append(child)

        while queue:
            curr = queue.popleft()
            for ch, child in curr.children.items():
                fail_state = curr.fail
                while fail_state is not None and ch not in fail_state.children:
                    fail_state = fail_state.fail

                child.fail = fail_state.children[ch] if fail_state is not None else self.root
                # Inherit outputs from failure state
                child.output.update(child.fail.output)
                queue.append(child)

    def search(self, text: str) -> List[Tuple[int, int, str]]:
        """Search text and return list of (start_idx, end_idx, matched_keyword)."""
        text_norm = text.lower()
        results: List[Tuple[int, int, str]] = []
        curr = self.root

        for idx, ch in enumerate(text_norm):
            while curr is not None and ch not in curr.children:
                curr = curr.fail

            if curr is None:
                curr = self.root
                continue

            curr = curr.children[ch]
            for kw in curr.output:
                start = idx - len(kw) + 1
                end = idx + 1
                results.append((start, end, kw))

        return results

    def contains_any(self, text: str) -> bool:
        """Fast boolean check: returns True upon encountering the first matching keyword."""
        text_norm = text.lower()
        curr = self.root

        for ch in text_norm:
            while curr is not None and ch not in curr.children:
                curr = curr.fail

            if curr is None:
                curr = self.root
                continue

            curr = curr.children[ch]
            if curr.output:
                return True

        return False

    @property
    def pattern_count(self) -> int:
        return self._keywords_count
