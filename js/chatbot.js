/**
 * StackOps AI Chatbot Widget
 * Integrates with main server.js
 * This chatbot handles consultations, appointments, and general Q&A
 */

class StackOpsChatbot {
    constructor() {
        this.API_URL = window.location.origin; // Uses main server
        this.sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        this.inBookingFlow = false; // Flag to track if we're actively in a booking flow
        
        // Initialize visitor data - check localStorage first for existing bookings
        const savedBooking = localStorage.getItem('stackops_booking');
        const parsedBooking = savedBooking ? JSON.parse(savedBooking) : null;
        
        this.visitorData = {
            name: parsedBooking?.name || null,
            companyName: parsedBooking?.companyName || null,
            title: parsedBooking?.title || null,
            email: parsedBooking?.email || null,
            phone: parsedBooking?.phone || null,
            service: parsedBooking?.service || null,
            date: parsedBooking?.date || null,
            time: parsedBooking?.time || null,
            additionalNotes: parsedBooking?.additionalNotes || null
        };
        
        this.STACKOPS_LOGO = `
            <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
                <defs>
                    <linearGradient id="msgLogoGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" style="stop-color:#0066FF;stop-opacity:1" />
                        <stop offset="100%" style="stop-color:#0052CC;stop-opacity:1" />
                    </linearGradient>
                </defs>
                <path d="M20 30 L35 15 L65 15 L80 30 L80 70 L65 85 L35 85 L20 70 Z" fill="url(#msgLogoGrad)"/>
                <path d="M30 40 L40 30 L60 30 L70 40 L70 60 L60 70 L40 70 L30 60 Z" fill="#0066FF" opacity="0.8"/>
                <circle cx="50" cy="50" r="8" fill="white"/>
            </svg>
        `;

        this.init();
    }

    init() {
        // Only initialize if chatbot widget doesn't already exist
        if (document.getElementById('chatbot-widget')) {
            return;
        }

        this.createWidget();
        this.attachEventListeners();
    }

    createWidget() {
        const chatbotHTML = `
            <style>
                .chatbot-widget {
                    position: fixed;
                    bottom: 24px;
                    right: 24px;
                    z-index: 9999;
                }

                .main-toggle {
                    width: 64px;
                    height: 64px;
                    border-radius: 50%;
                    background: transparent;
                    backdrop-filter: blur(10px) saturate(180%);
                    -webkit-backdrop-filter: blur(10px) saturate(180%);
                    border: 2px solid rgba(255, 183, 77, 0.85);
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    box-shadow: 
                        0 8px 32px rgba(0, 0, 0, 0.15),
                        inset 0 1px 1px rgba(255, 255, 255, 0.35),
                        0 0 20px rgba(249, 115, 22, 0.65),
                        0 0 40px rgba(249, 115, 22, 0.45);
                    transition: all 0.3s;
                    padding: 0;
                    overflow: hidden;
                }

                .main-toggle img {
                    width: 58%;
                    height: 58%;
                    object-fit: contain;
                    display: block;
                    margin: auto;
                    animation: none !important;
                    transform: none !important;
                    filter: none;
                }

                .main-toggle.on {
                    background: transparent;
                    backdrop-filter: blur(10px);
                    -webkit-backdrop-filter: blur(10px);
                    border: 1px solid rgba(249, 115, 22, 0.75);
                    box-shadow: 
                        0 8px 32px rgba(0, 0, 0, 0.2),
                        0 0 25px rgba(249, 115, 22, 0.65),
                        0 0 50px rgba(249, 115, 22, 0.45);
                }

                .main-toggle:hover {
                    transform: scale(1.1);
                    background: transparent;
                    box-shadow: 
                        0 8px 32px rgba(0, 0, 0, 0.1),
                        inset 0 1px 1px rgba(255, 255, 255, 0.3),
                        0 0 25px rgba(249, 115, 22, 0.65),
                        0 0 50px rgba(249, 115, 22, 0.45);
                }

                .chat-corner {
                    position: fixed;
                    bottom: 100px;
                    right: 24px;
                    width: 420px;
                    max-height: 650px;
                    display: none;
                    flex-direction: column;
                    z-index: 9998;
                    animation: slideUp 0.3s ease-out;
                    background: transparent;
                    padding: 0;
                }

                .chat-corner.active {
                    display: flex;
                }

                @keyframes slideUp {
                    from {
                        opacity: 0;
                        transform: translateY(20px);
                    }
                    to {
                        opacity: 1;
                        transform: translateY(0);
                    }
                }

                .corner-controls {
                    display: flex;
                    gap: 8px;
                    justify-content: flex-end;
                    margin-bottom: 12px;
                }

                .mini-btn {
                    width: 44px;
                    height: 44px;
                    border-radius: 50%;
                    background: rgba(30, 41, 59, 0.9);
                    backdrop-filter: blur(10px);
                    border: 1px solid rgba(0, 110, 255, 0.3);
                    cursor: pointer;
                    font-size: 16px;
                    color: #e2e8f0;
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
                    transition: all 0.2s;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }

                .mini-btn.close-x {
                    color: #f87171;
                    font-size: 22px;
                }

                .mini-btn.close-x:hover {
                    background: rgba(239, 68, 68, 0.2);
                    border-color: rgba(239, 68, 68, 0.4);
                }

                .mini-btn:hover {
                    transform: scale(1.1);
                    box-shadow: 0 6px 16px rgba(0, 0, 0, 0.2);
                }

                .corner-messages {
                    max-height: 600px;
                    overflow-y: auto;
                    padding: 8px 0;
                    flex: 1;
                    background: transparent;
                }

                .corner-messages::-webkit-scrollbar {
                    width: 5px;
                }

                .corner-messages::-webkit-scrollbar-track {
                    background: transparent;
                }

                .corner-messages::-webkit-scrollbar-thumb {
                    background: rgba(0, 110, 255, 0.4);
                    border-radius: 3px;
                }

                .corner-messages::-webkit-scrollbar-thumb:hover {
                    background: rgba(0, 110, 255, 0.6);
                }

                .msg {
                    display: flex;
                    margin-bottom: 16px;
                    animation: popIn 0.4s cubic-bezier(0.4, 0, 0.2, 1);
                }

                @keyframes popIn {
                    from {
                        opacity: 0;
                        transform: translateY(15px);
                    }
                    to {
                        opacity: 1;
                        transform: translateY(0);
                    }
                }

                .msg.bot {
                    justify-content: flex-start;
                }

                .msg.user {
                    justify-content: flex-end;
                }

                .bot-icon {
                    width: 48px;
                    height: 48px;
                    flex-shrink: 0;
                    margin-right: 12px;
                    filter: drop-shadow(0 3px 10px rgba(0, 0, 0, 0.15));
                }

                .bot-icon svg {
                    width: 100%;
                    height: 100%;
                }

                .msg-wrapper {
                    display: flex;
                    flex-direction: column;
                    max-width: 340px;
                }

                .msg.user .msg-wrapper {
                    max-width: 300px;
                }

                .text-bubble {
                    background: rgba(30, 41, 59, 0.85);
                    backdrop-filter: blur(10px);
                    padding: 14px 18px;
                    border-radius: 18px;
                    font-size: 15px;
                    line-height: 1.5;
                    color: #e2e8f0;
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
                    border: 1px solid rgba(0, 110, 255, 0.2);
                    white-space: pre-wrap;
                    word-wrap: break-word;
                }

                .msg.bot .text-bubble {
                    border-bottom-left-radius: 6px;
                }

                .msg.user .text-bubble {
                    background: linear-gradient(135deg, #0066FF 0%, #0052CC 100%);
                    color: white;
                    border-bottom-right-radius: 6px;
                    border: 1px solid rgba(0, 110, 255, 0.4);
                }

                .typing-indicator {
                    display: none;
                }

                .typing-indicator.active {
                    display: flex;
                    margin-bottom: 16px;
                }

                .typing-anim {
                    padding: 16px 20px;
                    background: rgba(30, 41, 59, 0.85);
                    backdrop-filter: blur(10px);
                    border-radius: 18px;
                    border-bottom-left-radius: 6px;
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
                    border: 1px solid rgba(0, 110, 255, 0.2);
                }

                .dot-anim {
                    display: flex;
                    gap: 5px;
                }

                .dot-anim span {
                    width: 9px;
                    height: 9px;
                    background: #64748b;
                    border-radius: 50%;
                    animation: dotBounce 1.4s infinite;
                }

                .dot-anim span:nth-child(2) {
                    animation-delay: 0.2s;
                }

                .dot-anim span:nth-child(3) {
                    animation-delay: 0.4s;
                }

                @keyframes dotBounce {
                    0%, 60%, 100% {
                        transform: translateY(0);
                    }
                    30% {
                        transform: translateY(-8px);
                    }
                }

                .btn-group {
                    display: flex;
                    gap: 8px;
                    margin-top: 10px;
                    flex-wrap: wrap;
                }

                .opt-btn {
                    background: rgba(51, 65, 85, 0.8);
                    color: #e2e8f0;
                    border: 1.5px solid rgba(0, 110, 255, 0.3);
                    padding: 9px 18px;
                    border-radius: 18px;
                    font-size: 14px;
                    font-weight: 200;
                    cursor: pointer;
                    transition: all 0.2s;
                    box-shadow: 0 2px 6px rgba(0, 0, 0, 0.2);
                    min-height: 44px;
                }

                .opt-btn:hover {
                    background: #0066FF;
                    color: white;
                    border-color: #0066FF;
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(0, 102, 255, 0.3);
                }

                .chatbot-input-container {
                    display: flex;
                    gap: 8px;
                    padding: 12px 0;
                    background: transparent;
                    margin-top: 8px;
                }

                .chatbot-input {
                    flex: 1;
                    border: 1.5px solid rgba(0, 110, 255, 0.3);
                    border-radius: 18px;
                    padding: 10px 16px;
                    font-size: 14px;
                    outline: none;
                    transition: all 0.2s;
                    font-family: inherit;
                    background: rgba(15, 23, 42, 0.7);
                    color: #e2e8f0;
                }

                .chatbot-input:focus {
                    border-color: #0066FF;
                    box-shadow: 0 0 0 3px rgba(0, 102, 255, 0.2);
                    background: rgba(15, 23, 42, 0.9);
                }

                .chatbot-input::placeholder {
                    color: #94a3b8;
                }

                .chatbot-send {
                    background: #0066FF;
                    color: white;
                    border: none;
                    border-radius: 18px;
                    padding: 10px 16px;
                    cursor: pointer;
                    font-size: 16px;
                    transition: all 0.2s;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    min-width: 44px;
                }

                .chatbot-send:hover:not(:disabled) {
                    background: #0052CC;
                    transform: translateY(-1px);
                    box-shadow: 0 4px 12px rgba(0, 102, 255, 0.3);
                }

                .chatbot-send:disabled {
                    opacity: 0.6;
                    cursor: not-allowed;
                }

                @media (max-width: 1024px) {
                    .chatbot-widget {
                        bottom: 20px;
                        right: 20px;
                    }

                    .chat-corner {
                        bottom: 95px;
                        right: 20px;
                        width: 380px;
                        max-height: 550px;
                    }
                }

                @media (max-width: 768px) {
                    .chatbot-widget {
                        bottom: 16px;
                        right: 16px;
                    }

                    .main-toggle {
                        width: 56px;
                        height: 56px;
                    }

                    .chat-corner {
                        width: calc(100vw - 32px);
                        max-width: 380px;
                        max-height: 60vh;
                        right: 16px;
                        bottom: 80px;
                        left: auto;
                    }

                    .corner-messages {
                        max-height: calc(60vh - 140px);
                    }

                    .msg-wrapper {
                        max-width: calc(100vw - 100px);
                    }

                    .msg.user .msg-wrapper {
                        max-width: calc(100vw - 80px);
                    }

                    .text-bubble {
                        font-size: 14px;
                        padding: 12px 15px;
                    }

                    .chatbot-input {
                        font-size: 14px;
                        padding: 8px 12px;
                    }

                    .chatbot-send {
                        min-width: 40px;
                        padding: 8px 12px;
                    }

                    .opt-btn {
                        font-size: 13px;
                        padding: 8px 14px;
                    }
                }

                @media (max-width: 480px) {
                    .chatbot-widget {
                        bottom: 12px;
                        right: 12px;
                    }

                    .main-toggle {
                        width: 52px;
                        height: 52px;
                    }

                    .chat-corner {
                        width: calc(100vw - 24px);
                        max-width: 360px;
                        max-height: 65vh;
                        right: 12px;
                        bottom: 70px;
                    }

                    .corner-controls {
                        gap: 6px;
                        margin-bottom: 8px;
                    }

                    .mini-btn {
                        width: 40px;
                        height: 40px;
                        font-size: 14px;
                    }

                    .corner-messages {
                        max-height: calc(65vh - 130px);
                        padding: 6px 0;
                    }

                    .msg {
                        margin-bottom: 12px;
                    }

                    .text-bubble {
                        font-size: 13px;
                        padding: 10px 12px;
                        border-radius: 14px;
                    }

                    .msg.bot .text-bubble {
                        border-bottom-left-radius: 4px;
                    }

                    .msg.user .text-bubble {
                        border-bottom-right-radius: 4px;
                    }

                    .chatbot-input-container {
                        gap: 6px;
                        padding: 8px 0;
                        margin-top: 6px;
                    }

                    .chatbot-input {
                        font-size: 13px;
                        padding: 8px 10px;
                        border-radius: 16px;
                    }

                    .chatbot-send {
                        min-width: 38px;
                        padding: 8px 10px;
                        border-radius: 16px;
                    }

                    .btn-group {
                        gap: 6px;
                        margin-top: 8px;
                    }

                    .opt-btn {
                        font-size: 12px;
                        padding: 7px 12px;
                        min-height: 38px;
                        border-radius: 16px;
                    }

                    .bot-icon {
                        width: 40px;
                        height: 40px;
                        margin-right: 10px;
                    }

                    .msg-wrapper {
                        max-width: calc(100vw - 85px);
                    }

                    .msg.user .msg-wrapper {
                        max-width: calc(100vw - 50px);
                    }
                }

                /* The client portal phone layout reserves space for its fixed bottom navigation. */
                @media (max-width: 600px) {
                    .chatbot-widget {
                        bottom: 92px;
                    }

                    .chat-corner {
                        bottom: 156px;
                    }
                }
            </style>

            <div class="chatbot-widget" id="chatbot-widget">
                <button class="main-toggle" id="chatToggle">
                    <img src="Images/Logos/StackCTRLLoading.png" alt="StackOps Logo">
                </button>
            </div>

            <div class="chat-corner" id="chatCorner">
                <div class="corner-controls">
                    <button class="mini-btn" id="scrollDown">▼</button>
                    <button class="mini-btn close-x" id="closeChat">✕</button>
                </div>

                <div class="corner-messages" id="chatMessages"></div>

                <div class="chatbot-input-container">
                    <input 
                        type="text" 
                        id="messageInput" 
                        class="chatbot-input"
                        placeholder="Type your message..."
                        autocomplete="off"
                    />
                    <button id="sendButton" class="chatbot-send">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                            <line x1="22" y1="2" x2="11" y2="13"></line>
                            <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
                        </svg>
                    </button>
                </div>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', chatbotHTML);
    }

    attachEventListeners() {
        const chatToggle = document.getElementById('chatToggle');
        const chatCorner = document.getElementById('chatCorner');
        const chatMessages = document.getElementById('chatMessages');
        const messageInput = document.getElementById('messageInput');
        const sendButton = document.getElementById('sendButton');
        const closeChat = document.getElementById('closeChat');
        const scrollDown = document.getElementById('scrollDown');

        // Toggle chat
        chatToggle.addEventListener('click', () => {
            chatCorner.classList.toggle('active');
            chatToggle.classList.toggle('on');
            
            if (chatCorner.classList.contains('active')) {
                messageInput.focus();
                if (chatMessages.children.length === 0) {
                    // Get user's first name for personalized greeting
                    const userFirstName = sessionStorage.getItem('userFirstName') || 'there';
                    const isClientPortal = window.location.pathname.includes('ClientPortal.html');
                    
                    let greetingMessage;
                    if (isClientPortal) {
                        greetingMessage = `👋 Hi ${userFirstName}! I'm StackOn, your AI assistant.\n\nI can help you with:\n• Invoice details & payment\n• Account information\n• Cisco Duo license status\n\nWhat can I assist you with today?`;
                    } else {
                        greetingMessage = `👋 Hi! I'm StackOn, your AI assistant from StackOps IT Solutions.\n\nI can help you:\n• Learn about our services\n• Book a free consultation\n• Answer your tech questions\n\nWhat brings you here today?`;
                    }
                    
                    this.addMessage('bot', greetingMessage);
                }
            }
        });

        closeChat.addEventListener('click', () => {
            chatCorner.classList.remove('active');
            chatToggle.classList.remove('on');
        });

        scrollDown.addEventListener('click', () => {
            chatMessages.scrollTop = chatMessages.scrollHeight;
        });

        sendButton.addEventListener('click', () => this.sendMessage());
        messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.sendMessage();
            }
        });

        this.chatMessages = chatMessages;
        this.messageInput = messageInput;
        this.sendButton = sendButton;
    }


    async sendMessage() {
        const message = this.messageInput.value.trim();
        if (!message) return;

        this.addMessage('user', message);
        this.messageInput.value = '';
        this.sendButton.disabled = true;
        this.showTyping(true);

        // Detect if user wants to book
        const bookingKeywords = ['book', 'appointment', 'consultation', 'schedule', 'meeting', 'call', 'speak', 'discuss', 'contact'];
        const lowerMessage = message.toLowerCase();
        const wantsToBook = bookingKeywords.some(keyword => lowerMessage.includes(keyword));

        // Check if we have a completed booking
        const isBookingComplete = this.visitorData.name && this.visitorData.companyName && this.visitorData.email && this.visitorData.phone && this.visitorData.service && this.visitorData.date && this.visitorData.time && this.visitorData.additionalNotes !== null;
        
        // If user wants to book and already completed, reset for new booking
        if (wantsToBook && isBookingComplete) {
            this.inBookingFlow = false;
            this.visitorData = {
                name: null,
                companyName: null,
                title: null,
                email: null,
                phone: null,
                service: null,
                date: null,
                time: null,
                additionalNotes: null
            };
        }

        // User initiated booking flow
        if (wantsToBook) {
            this.inBookingFlow = true;
        }

        // Extract booking data if we're in booking flow
        if (this.inBookingFlow && !isBookingComplete) {
            // Extract the appropriate field based on what we have
            if (!this.visitorData.name && !message.includes('@') && !message.match(/\d{9,}/) && !message.match(/\d{4}-\d{2}-\d{2}/) && !message.match(/^\d{2}:\d{2}$/)) {
                this.visitorData.name = message;
            } else if (this.visitorData.name && !this.visitorData.companyName && !message.includes('@') && !message.match(/\d{9,}/) && !message.match(/\d{4}-\d{2}-\d{2}/) && !message.match(/^\d{2}:\d{2}$/)) {
                this.visitorData.companyName = message;
            } else if (this.visitorData.name && this.visitorData.companyName && !this.visitorData.email && message.includes('@')) {
                this.visitorData.email = message;
            } else if (this.visitorData.email && !this.visitorData.phone && message.match(/\d{9,}/)) {
                this.visitorData.phone = message;
            } else if (this.visitorData.phone && !this.visitorData.service && !message.match(/\d{4}-\d{2}-\d{2}/) && !message.match(/^\d{2}:\d{2}$/)) {
                this.visitorData.service = message;
            } else if (this.visitorData.service && !this.visitorData.date && message.match(/\d{4}-\d{2}-\d{2}/)) {
                this.visitorData.date = message.match(/\d{4}-\d{2}-\d{2}/)[0];
            } else if (this.visitorData.date && !this.visitorData.time && message.match(/^\d{2}:\d{2}$/)) {
                this.visitorData.time = message;
            } else if (this.visitorData.time && this.visitorData.additionalNotes === null) {
                this.visitorData.additionalNotes = message;
            }
        }

        try {
            const token = localStorage.getItem('authToken');
            const headers = { 'Content-Type': 'application/json' };
            
            if (token) {
                headers['Authorization'] = `Bearer ${token}`;
            }

            const response = await fetch(`${this.API_URL}/api/chat`, {
                method: 'POST',
                headers: headers,
                body: JSON.stringify({
                    message,
                    sessionId: this.sessionId,
                    visitorName: this.visitorData.name,
                    visitorCompanyName: this.visitorData.companyName,
                    visitorEmail: this.visitorData.email,
                    visitorPhone: this.visitorData.phone,
                    bookingService: this.visitorData.service,
                    bookingDate: this.visitorData.date,
                    bookingTime: this.visitorData.time,
                    bookingNotes: this.visitorData.additionalNotes
                })
            });

            const data = await response.json();
            this.showTyping(false);

            if (data.success) {
                this.addMessage('bot', data.message, data.options);
                
                // If booking was successful, reset booking flow
                if (data.message.includes('been booked') || data.message.includes('successfully booked')) {
                    localStorage.setItem('stackops_booking', JSON.stringify(this.visitorData));
                    this.inBookingFlow = false;
                    
                    this.visitorData = {
                        name: null,
                        companyName: null,
                        title: null,
                        email: null,
                        phone: null,
                        service: null,
                        date: null,
                        time: null,
                        additionalNotes: null
                    };
                }
            } else {
                this.addMessage('bot', "Oops! Something went wrong on my end. Mind trying that again?");
            }

        } catch (error) {
            this.showTyping(false);
            this.addMessage('bot', "Hmm, I'm having trouble connecting. Could you refresh the page and try again?");
            console.error('Chatbot error:', error);
        } finally {
            this.sendButton.disabled = false;
            this.messageInput.focus();
        }
    }

    addMessage(sender, text, options = null) {
        const msgDiv = document.createElement('div');
        msgDiv.className = `msg ${sender}`;

        if (sender === 'bot') {
            msgDiv.innerHTML = `
                <div class="bot-icon">${this.STACKOPS_LOGO}</div>
                <div class="msg-wrapper">
                    <div class="text-bubble">${this.escapeHtml(text)}</div>
                </div>
            `;
        } else {
            msgDiv.innerHTML = `
                <div class="msg-wrapper">
                    <div class="text-bubble">${this.escapeHtml(text)}</div>
                </div>
            `;
        }

        this.chatMessages.appendChild(msgDiv);

        // Add options if provided
        if (options && options.length > 0 && sender === 'bot') {
            const btnGroup = document.createElement('div');
            btnGroup.className = 'btn-group';

            options.forEach(option => {
                const btn = document.createElement('button');
                btn.className = 'opt-btn';
                btn.textContent = option;
                btn.onclick = () => {
                    this.messageInput.value = option;
                    this.sendMessage();
                };
                btnGroup.appendChild(btn);
            });

            msgDiv.querySelector('.msg-wrapper').appendChild(btnGroup);
        }

        this.chatMessages.scrollTop = this.chatMessages.scrollHeight;
    }

    showTyping(show) {
        let typingIndicator = this.chatMessages.querySelector('.typing-indicator');
        
        if (show) {
            if (!typingIndicator) {
                typingIndicator = document.createElement('div');
                typingIndicator.className = 'typing-indicator active msg bot';
                typingIndicator.innerHTML = `
                    <div class="bot-icon">${this.STACKOPS_LOGO}</div>
                    <div class="msg-wrapper">
                        <div class="typing-anim">
                            <div class="dot-anim">
                                <span></span>
                                <span></span>
                                <span></span>
                            </div>
                        </div>
                    </div>
                `;
                this.chatMessages.appendChild(typingIndicator);
            }
        } else {
            if (typingIndicator) {
                typingIndicator.remove();
            }
        }

        this.chatMessages.scrollTop = this.chatMessages.scrollHeight;
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Global function to initialize chatbot after login
window.initChatbot = function() {
    // Only initialize if not already initialized
    if (!document.getElementById('chatbot-widget')) {
        new StackOpsChatbot();
    }
};

// For non-ClientPortal pages: Initialize chatbot when DOM is ready
// But NOT for ClientPortal - it will be initialized after login
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        // Only auto-initialize if NOT on ClientPortal page
        if (!window.location.pathname.includes('ClientPortal.html')) {
            new StackOpsChatbot();
        }
    });
} else {
    // Only auto-initialize if NOT on ClientPortal page
    if (!window.location.pathname.includes('ClientPortal.html')) {
        new StackOpsChatbot();
    }
}
