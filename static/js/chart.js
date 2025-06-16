function renderPerformanceChart(data) {
    const ctx = document.getElementById('chart').getContext('2d');
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: Object.keys(data),
            datasets: [{
                label: 'Time Taken (ms)',
                data: Object.values(data),
                backgroundColor: [
                    '#1abc9c',
                    '#3498db',
                    '#9b59b6',
                    '#f39c12',
                    '#e74c3c'
                ]
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { display: false },
                title: { display: true, text: 'Algorithm Performance Comparison' }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: { display: true, text: 'Time (ms)' }
                }
            }
        }
    });
}
