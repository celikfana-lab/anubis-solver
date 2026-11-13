# web/ — the documentation and comparison site
#
#   make serve      # http://127.0.0.1:8090/ — no build step, it is static
#   make check      # links, ids, tag balance, then layout at 390 and 1280
#
# There is nothing to compile. The pages are hand-written HTML with one shared
# stylesheet, so the site works from a filesystem, from any static server, from
# GitHub Pages, and offline.

PORT ?= 8090

.PHONY: serve check check-quick

serve:
	@echo "http://127.0.0.1:$(PORT)/"
	@python3 -m http.server $(PORT) --bind 127.0.0.1

# links, anchors, ids, tag balance, no remote subresources
check-quick:
	@python3 check.py

# ...plus the browser layout check, which starts and stops its own server
check:
	@./check.sh
