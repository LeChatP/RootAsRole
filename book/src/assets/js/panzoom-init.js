window.addEventListener("DOMContentLoaded", () => {
  // Cible toutes les balises <object> ou <iframe> avec la classe 'zoomable-svg'
  const svgObjects = document.querySelectorAll("object.zoomable-svg");

  svgObjects.forEach((obj) => {
    obj.addEventListener("load", () => {
      try {
        svgPanZoom(obj, {
          zoomEnabled: true,
          controlIconsEnabled: true, // Affiche des boutons [+] [-] [Reset]
          fit: true,
          center: true,
          minZoom: 0.5,
          maxZoom: 10
        });
      } catch (err) {
        console.error("Erreur d'initialisation svg-pan-zoom :", err);
      }
    });
  });
});