// cranix site: scroll reveal, hero parallax, header state and copy buttons.
// No dependencies and no network requests.

const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

function setUpReveal() {
    const items = document.querySelectorAll('.reveal');
    if (!('IntersectionObserver' in window) || reducedMotion.matches) {
        items.forEach(item => item.classList.add('is-visible'));
        return;
    }

    const observer = new IntersectionObserver(entries => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('is-visible');
                observer.unobserve(entry.target);
            }
        });
    }, { rootMargin: '0px 0px -8% 0px', threshold: 0.12 });

    // Children of a stagger group reveal one after another.
    document.querySelectorAll('[data-stagger]').forEach(group => {
        Array.from(group.children).forEach((child, index) => {
            child.style.setProperty('--reveal-delay', `${Math.min(index, 8) * 70}ms`);
        });
    });

    items.forEach(item => observer.observe(item));
}

function setUpScrollEffects() {
    const header = document.querySelector('.site-header');
    const hero = document.querySelector('.hero');
    let ticking = false;

    const update = () => {
        ticking = false;
        const y = window.scrollY;
        if (header) {
            header.classList.toggle('is-scrolled', y > 8);
        }
        // Parallax is limited to the hero and stops once it is out of view.
        if (hero && !reducedMotion.matches && y < hero.offsetHeight * 1.2) {
            hero.style.setProperty('--scroll', y.toFixed(1));
        }
    };

    window.addEventListener('scroll', () => {
        if (!ticking) {
            ticking = true;
            window.requestAnimationFrame(update);
        }
    }, { passive: true });
    update();
}

async function copyCommand(button) {
    const source = document.getElementById(button.dataset.copyTarget);
    if (!source) {
        return;
    }
    // Prompts are decoration; copy only the commands.
    const lines = Array.from(source.querySelectorAll('[data-command]')).map(line => line.textContent);
    const text = lines.length > 0 ? lines.join('\n') : source.textContent;
    const label = button.textContent;
    try {
        await navigator.clipboard.writeText(text);
        button.textContent = 'Copied';
        button.classList.add('is-copied');
    } catch (err) {
        button.textContent = 'Select it';
    }
    window.setTimeout(() => {
        button.textContent = label;
        button.classList.remove('is-copied');
    }, 1600);
}

function setUpCopyButtons() {
    document.querySelectorAll('[data-copy-target]').forEach(button => {
        button.hidden = false;
        button.addEventListener('click', () => copyCommand(button));
    });
}

document.documentElement.classList.add('js');
setUpReveal();
setUpScrollEffects();
setUpCopyButtons();
