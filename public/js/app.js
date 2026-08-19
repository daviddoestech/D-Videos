const searchForm = document.getElementById("searchForm");
const searchInput = document.getElementById("searchInput");
const videoGrid = document.getElementById("videoGrid");
const noResults = document.getElementById("noResults");
const refreshVideos = document.getElementById("refreshVideos");
const menuToggle = document.getElementById("menuToggle");
const sidebar = document.getElementById("sidebar");


// Mobile sidebar
menuToggle?.addEventListener("click", () => {
    sidebar?.classList.toggle("open");
});


// Search
searchForm?.addEventListener("submit", (event) => {

    event.preventDefault();

    const query = searchInput.value
        .trim()
        .toLowerCase();

    const videos = document.querySelectorAll(".video-card");

    let found = 0;

    videos.forEach((video) => {

        const title =
            video.dataset.title?.toLowerCase() || "";

        const category =
            video.dataset.category?.toLowerCase() || "";

        const matches =
            !query ||
            title.includes(query) ||
            category.includes(query);

        video.style.display =
            matches ? "" : "none";

        if (matches) {
            found++;
        }

    });

    if (noResults) {
        noResults.hidden = found !== 0;
    }

    if (query) {
        document
            .getElementById("videos")
            ?.scrollIntoView({
                behavior: "smooth"
            });
    }

});


// Category filtering
document.querySelectorAll(".category").forEach((button) => {

    button.addEventListener("click", () => {

        document
            .querySelectorAll(".category")
            .forEach((item) => {
                item.classList.remove("active");
            });

        button.classList.add("active");

        const category =
            button.textContent.trim();

        const videos =
            document.querySelectorAll(".video-card");

        let found = 0;

        videos.forEach((video) => {

            const matches =
                category === "All" ||
                video.dataset.category === category;

            video.style.display =
                matches ? "" : "none";

            if (matches) {
                found++;
            }

        });

        if (noResults) {
            noResults.hidden = found !== 0;
        }

    });

});


// Refresh animation
refreshVideos?.addEventListener("click", () => {

    const button = refreshVideos;

    button.disabled = true;

    button.textContent = "↻ Refreshing...";

    setTimeout(() => {

        button.disabled = false;

        button.textContent = "↻ Refresh";

    }, 700);

});